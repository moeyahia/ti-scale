import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { MissionApiError } from "../missions";
import { canonicalJson, hashCanonical, sha256, type JsonValue } from "./canonical";
import type { ResearchExecutionBoundary } from "./ResearchExecutionBoundary";
import type {
  ExperimentWorkerResult,
  PreparedExperimentWorker,
} from "./IsolatedExperimentWorkerLauncher";
import { isolatedExperimentWorkerSourceSha256 } from "./IsolatedExperimentWorkerLauncher";
import {
  type PreparedLabEnvironment,
  type SyntheticBenchmarkFixture,
} from "./LabEnvironmentManager";
import {
  BUILT_IN_SYNTHETIC_BENCHMARK_FIXTURES,
  evaluateSyntheticResearchDecision,
  type LocalSyntheticScenarioEvaluation,
} from "./SyntheticResearchFixtures";
import {
  builtInResearchCampaignSetup,
  createBuiltInResearchEvaluationHarness,
} from "./BuiltInResearchCampaignSetup";
import type { PrivateResearchHoldoutRegistry } from "./PrivateResearchHoldout";
import { ExperimentExecutionPolicy } from "./ExperimentExecutionPolicy";
import type { PlannedExperiment } from "./ResearchOrchestrator";
import type { IntegrityAuthority } from "./IntegrityVerifier";
import { ResearchPromotionLifecycleRepository } from "./ResearchPromotionLifecycleRepository";
import {
  INITIAL_RESEARCH_CAMPAIGNS,
  type InitialResearchCampaignId,
  type ResearchBudgets,
} from "./ResearchTypes";
import {
  applyStrategyPatch,
  FORBIDDEN_STRATEGY_PATH_PREFIXES,
  validateStrategyBundle,
  validateStrategyPatch,
  type StrategyBundle,
  type StrategyPatchOperation,
} from "./StrategyBundleSchema";
import type {
  ResearchExecutionBindings,
  ResearchExecutionReceipt,
} from "./ResearchExecutionReceipts";
import type { BenchmarkSplit } from "./SecurityEvaluationHarness";

const HASH = /^[a-f0-9]{64}$/u;
const SAFE_SEED = /^[A-Za-z0-9._:-]{1,160}$/u;

export type ExecutableResearchStage = Extract<
  BenchmarkSplit,
  "development" | "validation" | "hidden_holdout"
>;

function stageStartStatus(
  stage: ExecutableResearchStage,
): "queued" | "benchmarked" {
  return stage === "development" ? "queued" : "benchmarked";
}

function stagePassAction(stage: ExecutableResearchStage):
  | "development_pass"
  | "validation_pass"
  | "hidden_holdout_pass" {
  return `${stage}_pass`;
}

function stageFailAction(stage: ExecutableResearchStage):
  | "development_fail"
  | "validation_fail"
  | "hidden_holdout_fail" {
  return `${stage}_fail`;
}

function stageTerminalStatus(
  stage: ExecutableResearchStage,
  passed: boolean,
): "benchmarked" | "early_aborted" | "failed" | "holdout_failed" {
  if (passed) return "benchmarked";
  if (stage === "development") return "early_aborted";
  return stage === "validation" ? "failed" : "holdout_failed";
}

function safeScenarioReference(context: RunContextRow): string {
  return context.scenario_split === "hidden_holdout"
    ? "private-hidden-holdout"
    : context.scenario_id;
}

export interface BenchmarkScenarioIdentity {
  readonly id: string;
  readonly environmentDigest: string;
}

export interface SyntheticBenchmarkFixtureProvider {
  fixtureFor(
    scenario: BenchmarkScenarioIdentity,
  ): SyntheticBenchmarkFixture | undefined;
}

export class InMemorySyntheticBenchmarkFixtureProvider
implements SyntheticBenchmarkFixtureProvider {
  readonly #fixtures: ReadonlyMap<string, SyntheticBenchmarkFixture>;

  constructor(fixtures: readonly SyntheticBenchmarkFixture[]) {
    this.#fixtures = new Map(fixtures.map((fixture) => [
      fixture.scenarioId,
      Object.freeze(structuredClone(fixture)),
    ]));
  }

  fixtureFor(
    scenario: BenchmarkScenarioIdentity,
  ): SyntheticBenchmarkFixture | undefined {
    const fixture = this.#fixtures.get(scenario.id);
    return fixture?.environmentDigest === scenario.environmentDigest
      ? fixture
      : undefined;
  }
}

export { BUILT_IN_SYNTHETIC_BENCHMARK_FIXTURES };

interface RunContextRow {
  readonly run_id: string;
  readonly run_status: ResearchExperimentRunRecord["status"];
  readonly seed: string;
  readonly experiment_id: string;
  readonly experiment_status: string;
  readonly experiment_updated_at: string;
  readonly campaign_id: string;
  readonly campaign_name: string;
  readonly campaign_status: string;
  readonly campaign_owner: string;
  readonly campaign_budgets_json: string;
  readonly charter_id: string;
  readonly charter_hash: string;
  readonly charter_approved_by: string;
  readonly charter_budgets_json: string;
  readonly dimension_id: string;
  readonly dimension_name: string;
  readonly dimension_schema_path: string;
  readonly scenario_id: string;
  readonly scenario_name: string;
  readonly scenario_split: "development" | "validation" | "hidden_holdout";
  readonly scenario_hash: string;
  readonly scenario_active: number;
  readonly scenario_budget_json: string;
  readonly scenario_environment_digest: string;
  readonly scenario_family_id: string;
  readonly baseline_strategy_id: string;
  readonly baseline_bundle_json: string;
  readonly baseline_bundle_hash: string;
  readonly baseline_status: string;
  readonly candidate_strategy_id: string;
  readonly candidate_bundle_json: string;
  readonly candidate_bundle_hash: string;
  readonly candidate_status: string;
  readonly patch_json: string;
  readonly patch_hash: string;
  readonly patch_policy_validation_json: string;
  readonly patch_base_strategy_id: string;
  readonly snapshot_id: string;
  readonly snapshot_family_id: string;
  readonly benchmark_snapshot_hash: string;
  readonly evaluator_version: string;
  readonly evaluator_hash: string;
  readonly tool_manifest_hash: string;
  readonly execution_environment_kind: string;
  readonly execution_environment_identity_hash: string;
  readonly public_llm_spec_hash: string | null;
  readonly context_pack_id: string;
}

interface ExistingRunRow {
  readonly id: string;
}

interface ExistingOwnedRunRow extends ExistingRunRow {
  readonly campaign_owner: string;
}

type TerminalRunStatus = Extract<
  ResearchExperimentRunRecord["status"],
  "completed" | "failed" | "cancelled" | "early_aborted"
>;

interface CancellationIdempotencyRecord {
  readonly schemaVersion: "ti-scale.research-cancellation-idempotency.v1";
  readonly requestHash: string;
  readonly runId: string;
  readonly state: "reserved" | "completed";
  readonly terminalStatus: TerminalRunStatus | null;
  readonly reservedAt: string;
  readonly completedAt: string | null;
}

interface DurableCancellationIntent {
  readonly schemaVersion: "ti-scale.research-cancellation-intent.v1";
  readonly requestHash: string;
  readonly runId: string;
  readonly actorId: string;
  readonly reason: string;
  readonly promotionIdempotencyKey: string;
  readonly state: "reserved" | "completed";
  readonly terminalStatus: TerminalRunStatus | null;
  readonly reservedAt: string;
  readonly completedAt: string | null;
}

export interface ResearchExperimentRunRecord {
  readonly id: string;
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly seed: string;
  readonly workerId: string;
  readonly status:
    | "queued"
    | "running"
    | "completed"
    | "failed"
    | "cancelled"
    | "early_aborted";
  readonly startedAt: string | null;
  readonly endedAt: string | null;
  readonly createdAt: string;
}

interface RunRow {
  readonly id: string;
  readonly experiment_id: string;
  readonly scenario_id: string;
  readonly seed: string;
  readonly worker_id: string;
  readonly status: ResearchExperimentRunRecord["status"];
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly created_at: string;
}

function record(row: RunRow): ResearchExperimentRunRecord {
  return Object.freeze({
    id: row.id,
    experimentId: row.experiment_id,
    scenarioId: row.scenario_id,
    seed: row.seed,
    workerId: row.worker_id,
    status: row.status,
    startedAt: row.started_at,
    endedAt: row.ended_at,
    createdAt: row.created_at,
  });
}

function isTerminalRunStatus(
  status: ResearchExperimentRunRecord["status"],
): status is TerminalRunStatus {
  return ["completed", "failed", "cancelled", "early_aborted"].includes(
    status,
  );
}

function cancellationIntentSettingKey(runId: string): string {
  return `research.cancel.intent.${sha256(runId)}`;
}

function cancellationIdempotencySettingKey(
  actorId: string,
  idempotencyKey: string,
): string {
  return `idempotency.research.cancel.${sha256(actorId)}.${sha256(idempotencyKey)}`;
}

function parseCancellationIdempotencyRecord(
  value: string,
): CancellationIdempotencyRecord {
  const parsed = JSON.parse(value) as CancellationIdempotencyRecord;
  if (
    parsed.schemaVersion
      !== "ti-scale.research-cancellation-idempotency.v1"
    || !HASH.test(parsed.requestHash)
    || typeof parsed.runId !== "string"
    || !["reserved", "completed"].includes(parsed.state)
    || (
      parsed.terminalStatus !== null
      && !isTerminalRunStatus(parsed.terminalStatus)
    )
    || !Number.isFinite(Date.parse(parsed.reservedAt))
    || (
      parsed.completedAt !== null
      && !Number.isFinite(Date.parse(parsed.completedAt))
    )
  ) {
    throw new Error("Persisted Research cancellation idempotency is invalid.");
  }
  return parsed;
}

function parseDurableCancellationIntent(
  value: string,
): DurableCancellationIntent {
  const parsed = JSON.parse(value) as DurableCancellationIntent;
  if (
    parsed.schemaVersion !== "ti-scale.research-cancellation-intent.v1"
    || !HASH.test(parsed.requestHash)
    || typeof parsed.runId !== "string"
    || typeof parsed.actorId !== "string"
    || parsed.reason.trim().length < 3
    || parsed.reason.length > 1_000
    || typeof parsed.promotionIdempotencyKey !== "string"
    || !["reserved", "completed"].includes(parsed.state)
    || (
      parsed.terminalStatus !== null
      && !isTerminalRunStatus(parsed.terminalStatus)
    )
    || !Number.isFinite(Date.parse(parsed.reservedAt))
    || (
      parsed.completedAt !== null
      && !Number.isFinite(Date.parse(parsed.completedAt))
    )
  ) {
    throw new Error("Persisted Research cancellation intent is invalid.");
  }
  return parsed;
}

function executionError(
  status: number,
  code: string,
  humanMessage: string,
  category: string,
  remediation?: string,
): MissionApiError {
  return new MissionApiError(status, code, humanMessage, {
    humanMessage,
    category,
    ...(remediation ? { remediation } : {}),
  });
}

function runContext(
  database: SqliteDatabase,
  runId: string,
): RunContextRow {
  const row = database.prepare(`
    SELECT
      run.id AS run_id,
      run.status AS run_status,
      run.seed,
      experiment.id AS experiment_id,
      experiment.status AS experiment_status,
      experiment.updated_at AS experiment_updated_at,
      experiment.campaign_id,
      campaign.name AS campaign_name,
      campaign.status AS campaign_status,
      campaign.owner AS campaign_owner,
      campaign.budgets_json AS campaign_budgets_json,
      charter.id AS charter_id,
      charter.charter_hash,
      charter.approved_by AS charter_approved_by,
      charter.budgets_json AS charter_budgets_json,
      dimension.id AS dimension_id,
      dimension.name AS dimension_name,
      dimension.schema_path AS dimension_schema_path,
      scenario.id AS scenario_id,
      scenario.name AS scenario_name,
      scenario.split AS scenario_split,
      scenario.scenario_hash,
      scenario.active AS scenario_active,
      scenario.budget_json AS scenario_budget_json,
      scenario.environment_digest AS scenario_environment_digest,
      scenario.family_id AS scenario_family_id,
      baseline.id AS baseline_strategy_id,
      baseline.bundle_json AS baseline_bundle_json,
      baseline.bundle_hash AS baseline_bundle_hash,
      baseline.status AS baseline_status,
      candidate.id AS candidate_strategy_id,
      candidate.bundle_json AS candidate_bundle_json,
      candidate.bundle_hash AS candidate_bundle_hash,
      candidate.status AS candidate_status,
      patch.json_patch_json AS patch_json,
      patch.patch_hash,
      patch.policy_validation_json AS patch_policy_validation_json,
      patch.base_strategy_version_id AS patch_base_strategy_id,
      snapshot.id AS snapshot_id,
      snapshot.family_id AS snapshot_family_id,
      snapshot.snapshot_hash AS benchmark_snapshot_hash,
      family.evaluator_version,
      snapshot.evaluator_hash,
      snapshot.tool_manifest_hash,
      snapshot.execution_environment_kind,
      snapshot.execution_environment_identity_hash,
      experiment.public_llm_spec_hash,
      context_pack.id AS context_pack_id
    FROM experiment_runs run
    JOIN experiments experiment ON experiment.id = run.experiment_id
    JOIN research_campaigns campaign
      ON campaign.id = experiment.campaign_id
    JOIN benchmark_scenarios scenario ON scenario.id = run.scenario_id
    JOIN benchmark_snapshot_scenarios membership
      ON membership.snapshot_id = experiment.benchmark_snapshot_id
     AND membership.scenario_id = scenario.id
    JOIN research_charters charter
      ON charter.id = experiment.charter_id
    JOIN research_dimensions dimension
      ON dimension.id = experiment.dimension_id
    JOIN strategy_versions baseline
      ON baseline.id = experiment.baseline_strategy_id
    JOIN strategy_versions candidate
      ON candidate.id = experiment.candidate_strategy_id
    JOIN strategy_patches patch
      ON patch.strategy_version_id = candidate.id
    JOIN benchmark_snapshots snapshot
      ON snapshot.id = experiment.benchmark_snapshot_id
    JOIN benchmark_families family
      ON family.id = snapshot.family_id
    JOIN research_context_packs context_pack
      ON context_pack.id = (
        SELECT context.id
        FROM research_context_packs context
        WHERE context.experiment_id = experiment.id
        ORDER BY context.created_at, context.id
        LIMIT 1
      )
    WHERE run.id = ?
  `).get(runId) as RunContextRow | undefined;
  if (!row) {
    throw executionError(
      404,
      "research_experiment_run_not_found",
      "The requested Research experiment run does not exist.",
      "not_found",
    );
  }
  return row;
}

interface ValidatedRunContext {
  readonly catalogId: InitialResearchCampaignId;
  readonly setup: ReturnType<typeof builtInResearchCampaignSetup>;
  readonly baseline: StrategyBundle;
  readonly candidate: StrategyBundle;
  readonly patch: readonly StrategyPatchOperation[];
  readonly budgets: ResearchBudgets;
}

function campaignCatalogId(name: string): InitialResearchCampaignId {
  const definition = INITIAL_RESEARCH_CAMPAIGNS.find(
    ({ title }) => title === name,
  );
  if (!definition) {
    throw new Error(
      "Research campaign is not one of the three registered bounded tracks.",
    );
  }
  return definition.id;
}

function validateBudgets(value: unknown): value is ResearchBudgets {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const budget = value as Record<string, unknown>;
  const integerKeys = [
    "maxExperiments", "maxWallClockMs", "maxPublicLlmTokens",
    "maxToolCalls", "maxConcurrentExperiments", "maxFailures",
    "maxRetries", "maxPatchOperations", "maxTrialsPerDimension",
    "safetyFailureCircuitBreaker",
  ] as const;
  return integerKeys.every((key) =>
    Number.isSafeInteger(budget[key]) && Number(budget[key]) >= 0)
    && typeof budget.maxEstimatedCost === "number"
    && Number.isFinite(budget.maxEstimatedCost)
    && budget.maxEstimatedCost >= 0
    && Number(budget.maxExperiments) > 0
    && Number(budget.maxConcurrentExperiments) > 0
    && Number(budget.maxPatchOperations) > 0;
}

function validateRunContext(
  context: RunContextRow,
  boundary: ResearchExecutionBoundary,
  privateHoldout?: PrivateResearchHoldoutRegistry,
): ValidatedRunContext {
  const catalogId = campaignCatalogId(context.campaign_name);
  const executionEnvironment = boundary.executionEnvironment;
  const setup = builtInResearchCampaignSetup(
    catalogId,
    executionEnvironment,
    privateHoldout,
  );
  const baseline = JSON.parse(
    context.baseline_bundle_json,
  ) as StrategyBundle;
  const candidate = JSON.parse(
    context.candidate_bundle_json,
  ) as StrategyBundle;
  const patch = JSON.parse(context.patch_json) as StrategyPatchOperation[];
  const campaignBudgets = JSON.parse(context.campaign_budgets_json) as unknown;
  const charterBudgets = JSON.parse(context.charter_budgets_json) as unknown;
  const validation = validateStrategyPatch(patch, {
    approvedMutablePaths: [setup.path],
    forbiddenPathPrefixes: FORBIDDEN_STRATEGY_PATH_PREFIXES,
    maxOperations: 1,
  });
  const applied = validation.valid
    ? applyStrategyPatch(baseline, patch, {
        approvedMutablePaths: [setup.path],
        forbiddenPathPrefixes: FORBIDDEN_STRATEGY_PATH_PREFIXES,
        maxOperations: 1,
      })
    : undefined;
  const scenario = setup.scenarios.find(
    ({ id }) => id === context.scenario_id,
  );
  const failures = [
    context.campaign_status === "approved"
      || context.campaign_status === "running",
    context.charter_approved_by === context.campaign_owner,
    context.dimension_name === setup.dimensionId,
    context.dimension_schema_path === setup.path,
    context.baseline_strategy_id === context.patch_base_strategy_id,
    context.baseline_bundle_hash === setup.baselineBundleHash,
    hashCanonical(baseline as unknown as JsonValue)
      === context.baseline_bundle_hash,
    validateStrategyBundle(baseline).length === 0,
    context.baseline_status === "verified",
    context.candidate_bundle_hash === setup.candidateBundleHash,
    hashCanonical(candidate as unknown as JsonValue)
      === context.candidate_bundle_hash,
    validateStrategyBundle(candidate).length === 0,
    context.candidate_status === "queued"
      || context.candidate_status === "running"
      || context.candidate_status === "benchmarked",
    validation.valid,
    validation.normalizedPatch.length === 1,
    hashCanonical(
      validation.normalizedPatch as unknown as JsonValue,
    ) === context.patch_hash,
    context.patch_hash === setup.patchHash,
    applied?.bundleHash === context.candidate_bundle_hash,
    applied !== undefined
      && canonicalJson(applied.bundle as unknown as JsonValue)
        === canonicalJson(candidate as unknown as JsonValue),
    context.snapshot_id === setup.snapshot.id,
    context.snapshot_family_id === setup.family.id,
    context.scenario_family_id === setup.family.id,
    context.benchmark_snapshot_hash === setup.snapshot.snapshotHash,
    context.evaluator_hash === setup.snapshot.evaluatorHash,
    context.evaluator_version === setup.family.evaluatorVersion,
    context.tool_manifest_hash === setup.snapshot.toolManifestHash,
    context.execution_environment_kind === executionEnvironment.kind,
    context.execution_environment_identity_hash
      === executionEnvironment.identityHash,
    context.public_llm_spec_hash === null,
    scenario !== undefined,
    scenario?.split === context.scenario_split,
    context.scenario_split !== "hidden_holdout"
      || privateHoldout?.isPrivateScenario(context.scenario_id) === true,
    context.scenario_hash === scenario?.scenarioHash,
    context.scenario_environment_digest === scenario?.environmentDigest,
    context.scenario_budget_json === scenario?.budgetJson,
    context.scenario_active === 1,
    validateBudgets(campaignBudgets),
    validateBudgets(charterBudgets),
    canonicalJson(campaignBudgets as JsonValue)
      === canonicalJson(charterBudgets as JsonValue),
  ];
  if (failures.some((value) => !value)) {
    throw new Error(
      "Research execution context differs from its reviewed campaign, charter, strategy, benchmark, or local-bwrap binding.",
    );
  }
  return {
    catalogId,
    setup,
    baseline,
    candidate,
    patch,
    budgets: campaignBudgets as ResearchBudgets,
  };
}

function immutableExecutionContextFingerprint(context: RunContextRow): string {
  return hashCanonical({
    runId: context.run_id,
    seedHash: sha256(context.seed),
    experimentId: context.experiment_id,
    campaignId: context.campaign_id,
    campaignOwner: context.campaign_owner,
    campaignBudgets: JSON.parse(context.campaign_budgets_json) as JsonValue,
    charterId: context.charter_id,
    charterHash: context.charter_hash,
    charterApprovedBy: context.charter_approved_by,
    charterBudgets: JSON.parse(context.charter_budgets_json) as JsonValue,
    dimensionId: context.dimension_id,
    dimensionName: context.dimension_name,
    dimensionPath: context.dimension_schema_path,
    scenarioId: context.scenario_id,
    scenarioHash: context.scenario_hash,
    scenarioEnvironmentDigest: context.scenario_environment_digest,
    baselineStrategyId: context.baseline_strategy_id,
    baselineStrategyHash: context.baseline_bundle_hash,
    candidateStrategyId: context.candidate_strategy_id,
    candidateStrategyHash: context.candidate_bundle_hash,
    patchHash: context.patch_hash,
    snapshotId: context.snapshot_id,
    snapshotHash: context.benchmark_snapshot_hash,
    evaluatorHash: context.evaluator_hash,
    toolManifestHash: context.tool_manifest_hash,
    executionEnvironmentKind: context.execution_environment_kind,
    executionEnvironmentIdentityHash:
      context.execution_environment_identity_hash,
    contextPackId: context.context_pack_id,
  } as unknown as JsonValue);
}

function nextSequence(database: SqliteDatabase, experimentId: string): number {
  const row = database.prepare(`
    SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence
    FROM experiment_events
    WHERE experiment_id = ?
  `).get(experimentId) as { readonly sequence: number };
  return row.sequence;
}

function appendEvent(
  database: SqliteDatabase,
  input: {
    readonly experimentId: string;
    readonly runId: string;
    readonly eventType: string;
    readonly summary: string;
    readonly payload: JsonValue;
    readonly occurredAt: string;
  },
): void {
  database.prepare(`
    INSERT INTO experiment_events (
      id, experiment_id, experiment_run_id, sequence, event_type,
      summary, payload_json, sensitivity, occurred_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'internal', ?)
  `).run(
    `research_event_${randomUUID()}`,
    input.experimentId,
    input.runId,
    nextSequence(database, input.experimentId),
    input.eventType,
    input.summary,
    canonicalJson(input.payload),
    input.occurredAt,
  );
}

function persistReceipt(
  database: SqliteDatabase,
  receipt: ResearchExecutionReceipt,
): void {
  database.prepare(`
    INSERT INTO research_execution_receipts (
      id, receipt_kind, experiment_id, scenario_id, boot_id, key_id,
      benchmark_snapshot_hash, evaluator_hash, tool_manifest_hash,
      reset_generation, challenge_hash, subject_identity_hash, evidence_hash,
      payload_json, algorithm, signature, issued_at, expires_at,
      consumed_at, consumed_by_run_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
  `).run(
    receipt.receiptId,
    receipt.kind,
    receipt.experimentId,
    receipt.scenarioId,
    receipt.bootId,
    receipt.keyId,
    receipt.benchmarkSnapshotHash,
    receipt.evaluatorHash,
    receipt.toolManifestHash,
    receipt.resetGeneration,
    receipt.challengeHash,
    receipt.subjectIdentityHash,
    receipt.evidenceHash,
    canonicalJson(receipt as unknown as JsonValue),
    receipt.algorithm,
    receipt.signature,
    receipt.issuedAt,
    receipt.expiresAt,
  );
}

export interface EnqueueExperimentInput {
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly seed: string;
  readonly actorId: string;
  readonly idempotencyKey: string;
}

export interface EnqueueExperimentStageInput {
  readonly experimentId: string;
  readonly stage: Exclude<ExecutableResearchStage, "development">;
  readonly seed: string;
  readonly actorId: string;
  readonly idempotencyKey: string;
}

export interface CancelExperimentRunInput {
  readonly runId: string;
  readonly actorId: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

export interface CancelResearchCampaignInput {
  readonly campaignId: string;
  readonly actorId: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

function processStartTicks(processId: number): string | undefined {
  try {
    const value = readFileSync(`/proc/${processId}/stat`, "utf8");
    const close = value.lastIndexOf(")");
    return close < 0
      ? undefined
      : value.slice(close + 1).trim().split(/\s+/u)[19];
  } catch {
    return undefined;
  }
}

function terminateExactProcess(
  processId: number,
  expectedStartTicks: string,
): boolean {
  if (processStartTicks(processId) !== expectedStartTicks) return true;
  try {
    process.kill(processId, "SIGKILL");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") return false;
  }
  return processStartTicks(processId) !== expectedStartTicks;
}

async function terminateExactProcessAndWait(
  processId: number,
  expectedStartTicks: string,
  timeoutMs = 2_000,
): Promise<boolean> {
  if (processStartTicks(processId) !== expectedStartTicks) return true;
  try {
    process.kill(processId, "SIGKILL");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") return false;
  }
  const deadline = Date.now() + timeoutMs;
  do {
    if (processStartTicks(processId) !== expectedStartTicks) return true;
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  } while (Date.now() < deadline);
  return false;
}

export class ExperimentRunner {
  readonly #database: SqliteDatabase;
  readonly #boundary: ResearchExecutionBoundary;
  readonly #fixtures: SyntheticBenchmarkFixtureProvider;
  readonly #privateHoldout?: PrivateResearchHoldoutRegistry;
  readonly #integrityAuthority: IntegrityAuthority;
  readonly #executionPolicy = new ExperimentExecutionPolicy();
  readonly #clock: () => Date;
  readonly #activeWorkers = new Map<string, PreparedExperimentWorker>();
  readonly #activeLabs = new Map<string, PreparedLabEnvironment>();
  readonly #activeTasks = new Map<string, Promise<void>>();
  readonly #activeCancellations =
    new Map<string, Promise<ResearchExperimentRunRecord>>();
  readonly #cancelRequested = new Set<string>();
  private queue: Promise<void> = Promise.resolve();
  private started = false;
  private stopping = false;

  constructor(input: {
    readonly database: SqliteDatabase;
    readonly boundary: ResearchExecutionBoundary;
    readonly integrityAuthority: IntegrityAuthority;
    readonly fixtures?: SyntheticBenchmarkFixtureProvider;
    readonly privateHoldout?: PrivateResearchHoldoutRegistry;
    readonly clock?: () => Date;
  }) {
    this.#database = input.database;
    this.#boundary = input.boundary;
    this.#integrityAuthority = input.integrityAuthority;
    this.#fixtures = input.fixtures
      ?? new InMemorySyntheticBenchmarkFixtureProvider(
        BUILT_IN_SYNTHETIC_BENCHMARK_FIXTURES,
      );
    this.#privateHoldout = input.privateHoldout;
    this.#clock = input.clock ?? (() => new Date());
  }

  read(runId: string): ResearchExperimentRunRecord {
    const row = this.#database.prepare(`
      SELECT id, experiment_id, scenario_id, seed, worker_id, status,
        started_at, ended_at, created_at
      FROM experiment_runs
      WHERE id = ?
    `).get(runId) as RunRow | undefined;
    if (!row) {
      throw executionError(
        404,
        "research_experiment_run_not_found",
        "The requested Research experiment run does not exist.",
        "not_found",
      );
    }
    return record(row);
  }

  enqueue(input: EnqueueExperimentInput): ResearchExperimentRunRecord {
    return this.enqueueResolved(input, "development");
  }

  enqueueStage(
    input: EnqueueExperimentStageInput,
  ): ResearchExperimentRunRecord {
    const rows = this.#database.prepare(`
      SELECT scenario.id
      FROM experiments experiment
      JOIN benchmark_snapshot_scenarios membership
        ON membership.snapshot_id = experiment.benchmark_snapshot_id
      JOIN benchmark_scenarios scenario
        ON scenario.id = membership.scenario_id
      WHERE experiment.id = ?
        AND scenario.split = ?
        AND scenario.active = 1
      ORDER BY membership.ordinal, scenario.id
    `).all(input.experimentId, input.stage) as Array<{
      readonly id: string;
    }>;
    if (rows.length !== 1) {
      throw executionError(
        409,
        "research_stage_fixture_unavailable",
        input.stage === "hidden_holdout"
          ? "This experiment has no single configured private hidden-holdout fixture."
          : "This experiment has no single immutable validation fixture.",
        "readiness",
        "Review the immutable benchmark snapshot and trusted holdout configuration.",
      );
    }
    const scenarioId = rows[0]!.id;
    if (
      input.stage === "hidden_holdout"
      && this.#privateHoldout?.isPrivateScenario(scenarioId) !== true
    ) {
      throw executionError(
        503,
        "research_private_holdout_unavailable",
        "The trusted private hidden-holdout descriptor is not available to this local runner.",
        "dependency_unavailable",
        "Configure the hash-pinned operator-owned holdout descriptor and restart only the Research service.",
      );
    }
    return this.enqueueResolved({
      experimentId: input.experimentId,
      scenarioId,
      seed: input.seed,
      actorId: input.actorId,
      idempotencyKey: input.idempotencyKey,
    }, input.stage);
  }

  private enqueueResolved(
    input: EnqueueExperimentInput,
    expectedStage: ExecutableResearchStage,
  ): ResearchExperimentRunRecord {
    const requestHash = hashCanonical({
      experimentId: input.experimentId,
      scenarioId: input.scenarioId,
      seed: input.seed,
      stage: expectedStage,
    } as unknown as JsonValue);
    const settingKey =
      `idempotency.research.execute.${sha256(input.actorId)}.${sha256(input.idempotencyKey)}`;
    const result = inImmediateTransaction(this.#database, () => {
      const prior = this.#database.prepare(
        "SELECT value_json FROM settings WHERE key = ?",
      ).get(settingKey) as { readonly value_json: string } | undefined;
      if (prior) {
        const value = JSON.parse(prior.value_json) as {
          readonly requestHash: string;
          readonly runId: string;
        };
        if (value.requestHash !== requestHash) {
          throw executionError(
            409,
            "research_execution_idempotency_conflict",
            "This execution submission key was already used for different parameters.",
            "conflict",
            "Submit the materially different run with a new Idempotency-Key.",
          );
        }
        return this.read(value.runId);
      }
      if (!SAFE_SEED.test(input.seed)) {
        throw executionError(
          400,
          "research_seed_invalid",
          "Choose a short stable seed containing letters, numbers, dots, dashes, underscores, or colons.",
          "invalid_input",
        );
      }
      const existing = this.#database.prepare(`
        SELECT run.id, campaign.owner AS campaign_owner
        FROM experiment_runs run
        JOIN experiments experiment ON experiment.id = run.experiment_id
        JOIN research_campaigns campaign
          ON campaign.id = experiment.campaign_id
        WHERE run.experiment_id = ?
          AND run.scenario_id = ?
          AND run.seed = ?
      `).get(
        input.experimentId,
        input.scenarioId,
        input.seed,
      ) as ExistingOwnedRunRow | undefined;
      if (existing) {
        if (existing.campaign_owner !== input.actorId) {
          throw executionError(
            403,
            "research_campaign_owner_required",
            "Only the human campaign owner may start this experiment.",
            "authorization_denied",
          );
        }
        const now = this.#clock().toISOString();
        this.#database.prepare(`
          INSERT INTO settings (
            key, value_json, sensitivity, version, updated_by, updated_at
          ) VALUES (?, ?, 'private', 1, ?, ?)
        `).run(
          settingKey,
          canonicalJson({ requestHash, runId: existing.id } as unknown as JsonValue),
          input.actorId,
          now,
        );
        return this.read(existing.id);
      }
      if (this.stopping) {
        throw executionError(
          503,
          "research_execution_stopping",
          "Research execution is stopping and cannot accept new work.",
          "dependency_unavailable",
        );
      }
      const eligibility = this.#database.prepare(`
        SELECT
          experiment.status AS experiment_status,
          campaign.status AS campaign_status,
          campaign.owner AS campaign_owner,
          campaign.budgets_json AS campaign_budgets_json,
          charter.approved_by AS charter_approved_by,
          charter.budgets_json AS charter_budgets_json,
          scenario.active AS scenario_active,
          scenario.split AS scenario_split,
          scenario.family_id AS scenario_family_id,
          snapshot.family_id AS snapshot_family_id,
          snapshot.snapshot_hash AS benchmark_snapshot_hash,
          snapshot.evaluator_hash,
          snapshot.tool_manifest_hash,
          snapshot.execution_environment_kind,
          snapshot.execution_environment_identity_hash,
          (
            SELECT COUNT(*) FROM experiment_runs counted
            JOIN experiments owned ON owned.id = counted.experiment_id
            WHERE owned.campaign_id = campaign.id
          ) AS campaign_run_count,
          (
            SELECT COUNT(*) FROM experiment_runs active
            JOIN experiments owned ON owned.id = active.experiment_id
            WHERE owned.campaign_id = campaign.id
              AND active.status IN ('queued', 'running')
          ) AS active_run_count,
          (
            SELECT COUNT(*) FROM experiment_runs failed
            JOIN experiments owned ON owned.id = failed.experiment_id
            WHERE owned.campaign_id = campaign.id
              AND failed.status IN ('failed', 'early_aborted')
          ) AS failure_count
        FROM experiments experiment
        JOIN research_campaigns campaign
          ON campaign.id = experiment.campaign_id
        JOIN research_charters charter
          ON charter.id = experiment.charter_id
        JOIN benchmark_snapshots snapshot
          ON snapshot.id = experiment.benchmark_snapshot_id
        JOIN benchmark_snapshot_scenarios membership
          ON membership.snapshot_id = snapshot.id
         AND membership.scenario_id = ?
        JOIN benchmark_scenarios scenario
          ON scenario.id = membership.scenario_id
        WHERE experiment.id = ?
      `).get(input.scenarioId, input.experimentId) as {
        readonly experiment_status: string;
        readonly campaign_status: string;
        readonly campaign_owner: string;
        readonly campaign_budgets_json: string;
        readonly charter_approved_by: string;
        readonly charter_budgets_json: string;
        readonly scenario_active: number;
        readonly scenario_split: string;
        readonly scenario_family_id: string;
        readonly snapshot_family_id: string;
        readonly benchmark_snapshot_hash: string;
        readonly evaluator_hash: string;
        readonly tool_manifest_hash: string;
        readonly execution_environment_kind: string;
        readonly execution_environment_identity_hash: string;
        readonly campaign_run_count: number;
        readonly active_run_count: number;
        readonly failure_count: number;
      } | undefined;
      if (!eligibility) {
        throw executionError(
          404,
          "research_experiment_or_scenario_not_found",
          "The requested experiment or benchmark scenario does not exist.",
          "not_found",
        );
      }
      if (eligibility.campaign_owner !== input.actorId) {
        throw executionError(
          403,
          "research_campaign_owner_required",
          "Only the human campaign owner may start this experiment.",
          "authorization_denied",
        );
      }
      const lifecycle = new ResearchPromotionLifecycleRepository(
        this.#database,
        this.#integrityAuthority,
        this.#clock,
      ).get(input.experimentId);
      const stageReady = expectedStage === "development"
        ? lifecycle.state === "queued"
          && !lifecycle.milestones.developmentPassed
        : expectedStage === "validation"
          ? lifecycle.state === "running"
            && lifecycle.milestones.developmentPassed
            && !lifecycle.milestones.validationPassed
          : lifecycle.state === "benchmarked"
            && lifecycle.milestones.validationPassed
            && !lifecycle.milestones.hiddenHoldoutPassed;
      if (
        eligibility.experiment_status !== stageStartStatus(expectedStage)
        || eligibility.campaign_status !== "approved"
        || eligibility.charter_approved_by !== eligibility.campaign_owner
        || eligibility.scenario_active !== 1
        || eligibility.scenario_split !== expectedStage
        || !stageReady
        || (
          expectedStage === "hidden_holdout"
          && this.#privateHoldout?.isPrivateScenario(input.scenarioId) !== true
        )
        || eligibility.scenario_family_id !== eligibility.snapshot_family_id
        || !HASH.test(eligibility.benchmark_snapshot_hash)
        || !HASH.test(eligibility.evaluator_hash)
        || !HASH.test(eligibility.tool_manifest_hash)
        || eligibility.execution_environment_kind !== "local_bwrap"
        || eligibility.execution_environment_identity_hash
          !== this.#boundary.executionEnvironment.identityHash
      ) {
        throw executionError(
          409,
          "research_experiment_not_executable",
          `This experiment is not ready for its ordered ${expectedStage.replace("_", " ")} stage.`,
          "readiness",
          "Complete the preceding stage and review the campaign charter, immutable benchmark snapshot, and current lifecycle.",
        );
      }
      const campaignBudgets = JSON.parse(
        eligibility.campaign_budgets_json,
      ) as unknown;
      const charterBudgets = JSON.parse(
        eligibility.charter_budgets_json,
      ) as unknown;
      if (
        !validateBudgets(campaignBudgets)
        || !validateBudgets(charterBudgets)
        || canonicalJson(campaignBudgets as unknown as JsonValue)
          !== canonicalJson(charterBudgets as unknown as JsonValue)
        || eligibility.campaign_run_count >= campaignBudgets.maxExperiments
        || eligibility.active_run_count
          >= campaignBudgets.maxConcurrentExperiments
        || eligibility.failure_count >= campaignBudgets.maxFailures
      ) {
        throw executionError(
          409,
          "research_campaign_budget_exhausted",
          "The approved Research campaign has reached an experiment, concurrency, or failure budget.",
          "budget_exhausted",
          "Stop, review, or create a new human-approved campaign charter; the runner will not widen budgets automatically.",
        );
      }
      const now = this.#clock().toISOString();
      const runId = `experiment_run_${randomUUID()}`;
      this.#database.prepare(`
        INSERT INTO experiment_runs (
          id, experiment_id, scenario_id, seed, worker_id, status,
          started_at, ended_at, created_at
        ) VALUES (?, ?, ?, ?, 'pending', 'queued', NULL, NULL, ?)
      `).run(
        runId,
        input.experimentId,
        input.scenarioId,
        input.seed,
        now,
      );
      appendEvent(this.#database, {
        experimentId: input.experimentId,
        runId,
        eventType: "experiment_run.queued",
        summary:
          `A bounded ${expectedStage.replace("_", " ")} benchmark run entered the durable local queue.`,
        payload: {
          scenarioId: expectedStage === "hidden_holdout"
            ? "private-hidden-holdout"
            : input.scenarioId,
          stage: expectedStage,
          seedHash: sha256(input.seed),
          liveClientTargetAllowed: false,
        },
        occurredAt: now,
      });
      this.#database.prepare(`
        INSERT INTO settings (
          key, value_json, sensitivity, version, updated_by, updated_at
        ) VALUES (?, ?, 'private', 1, ?, ?)
      `).run(
        settingKey,
        canonicalJson({ requestHash, runId } as unknown as JsonValue),
        input.actorId,
        now,
      );
      return this.read(runId);
    });
    if (this.started) this.schedule(result.id);
    return result;
  }

  private durableCancellationIntent(
    runId: string,
  ): DurableCancellationIntent | undefined {
    const row = this.#database.prepare(
      "SELECT value_json FROM settings WHERE key = ?",
    ).get(cancellationIntentSettingKey(runId)) as {
      readonly value_json: string;
    } | undefined;
    return row
      ? parseDurableCancellationIntent(row.value_json)
      : undefined;
  }

  private cancellationPending(runId: string): boolean {
    if (this.#cancelRequested.has(runId)) return true;
    return this.durableCancellationIntent(runId) !== undefined;
  }

  private completeCancellationSettings(
    intent: DurableCancellationIntent,
    terminalStatus: TerminalRunStatus,
    completedAt: string,
  ): void {
    const completedIntent: DurableCancellationIntent = {
      ...intent,
      state: "completed",
      terminalStatus,
      completedAt,
    };
    const intentUpdate = this.#database.prepare(`
      UPDATE settings
      SET value_json = ?, version = version + 1,
        updated_by = ?, updated_at = ?
      WHERE key = ?
    `).run(
      canonicalJson(completedIntent as unknown as JsonValue),
      intent.actorId,
      completedAt,
      cancellationIntentSettingKey(intent.runId),
    );
    if (intentUpdate.changes !== 1) {
      throw new Error(
        "Durable Research cancellation intent disappeared before completion.",
      );
    }
    const idempotencyRows = this.#database.prepare(`
      SELECT key, value_json
      FROM settings
      WHERE key LIKE 'idempotency.research.cancel.%'
        AND json_extract(value_json, '$.runId') = ?
    `).all(intent.runId) as Array<{
      readonly key: string;
      readonly value_json: string;
    }>;
    for (const row of idempotencyRows) {
      const stored = parseCancellationIdempotencyRecord(row.value_json);
      if (stored.state === "completed") continue;
      const update = this.#database.prepare(`
        UPDATE settings
        SET value_json = ?, version = version + 1,
          updated_by = ?, updated_at = ?
        WHERE key = ?
      `).run(
        canonicalJson({
          ...stored,
          state: "completed",
          terminalStatus,
          completedAt,
        } as unknown as JsonValue),
        intent.actorId,
        completedAt,
        row.key,
      );
      if (update.changes !== 1) {
        throw new Error(
          "Research cancellation idempotency disappeared before completion.",
        );
      }
    }
  }

  private finalizeCancellation(
    context: RunContextRow,
    intent: DurableCancellationIntent,
    cleanupVerified: boolean,
  ): ResearchExperimentRunRecord {
    if (!cleanupVerified) {
      this.fail(
        context,
        new Error(
          "Cancellation could not prove that the exact isolated worker and disposable fixture were removed.",
        ),
        false,
      );
      const failed = this.read(intent.runId);
      const failedStatus = failed.status;
      if (isTerminalRunStatus(failedStatus)) {
        inImmediateTransaction(this.#database, () => {
          this.completeCancellationSettings(
            intent,
            failedStatus,
            failed.endedAt ?? this.#clock().toISOString(),
          );
        });
      }
      return failed;
    }
    const now = this.#clock().toISOString();
    const terminalHash = hashCanonical({
      runId: intent.runId,
      outcome: "cancelled",
      reason: intent.reason,
      cleanupVerified,
      endedAt: now,
    } as unknown as JsonValue);
    return inImmediateTransaction(this.#database, () => {
      const live = this.read(intent.runId);
      if (isTerminalRunStatus(live.status)) {
        this.completeCancellationSettings(intent, live.status, now);
        return live;
      }
      if (live.status === "running") {
        const admissionUpdate = this.#database.prepare(`
          UPDATE research_experiment_admissions
          SET status = 'cancelled', ended_at = ?,
            terminal_result_hash = ?
          WHERE experiment_run_id = ? AND status = 'running'
        `).run(now, terminalHash, intent.runId);
        if (admissionUpdate.changes !== 1) {
          throw new Error(
            "Running Research cancellation lost its exact admission.",
          );
        }
      }
      const runUpdate = this.#database.prepare(`
        UPDATE experiment_runs
        SET status = 'cancelled', ended_at = ?
        WHERE id = ? AND status = ?
      `).run(now, intent.runId, live.status);
      if (runUpdate.changes !== 1) {
        throw new Error(
          "Research cancellation lost its reserved run transition.",
        );
      }
      const promotions = new ResearchPromotionLifecycleRepository(
        this.#database,
        this.#integrityAuthority,
        this.#clock,
      );
      const lifecycle = promotions.get(context.experiment_id);
      if (["queued", "running", "benchmarked"].includes(lifecycle.state)) {
        promotions.applyHumanTransition({
          experimentId: context.experiment_id,
          expectedVersion: lifecycle.version,
          action: "reject",
          actorId: intent.actorId,
          rationale: intent.reason,
          evidenceRefs: [
            `experiment-run:${intent.runId}`,
            `cancellation-result:${terminalHash}`,
          ],
          idempotencyKey: intent.promotionIdempotencyKey,
        });
      }
      appendEvent(this.#database, {
        experimentId: context.experiment_id,
        runId: intent.runId,
        eventType: "experiment_run.cancelled",
        summary: live.status === "queued"
          ? "The campaign owner cancelled the durable queued Research run before worker admission."
          : "The campaign owner cancelled the bounded Research run and the exact worker stopped.",
        payload: {
          reason: intent.reason,
          cleanupVerified,
          terminalHash,
          cancellationReservedAt: intent.reservedAt,
        },
        occurredAt: now,
      });
      this.completeCancellationSettings(intent, "cancelled", now);
      return this.read(intent.runId);
    });
  }

  private reserveCancellation(
    input: CancelExperimentRunInput,
    reason: string,
  ): {
    readonly run: ResearchExperimentRunRecord;
    readonly intent?: DurableCancellationIntent;
  } {
    const requestHash = hashCanonical({
      runId: input.runId,
      reason,
    } as unknown as JsonValue);
    const idempotencySettingKey = cancellationIdempotencySettingKey(
      input.actorId,
      input.idempotencyKey,
    );
    return inImmediateTransaction(this.#database, () => {
      const prior = this.#database.prepare(
        "SELECT value_json FROM settings WHERE key = ?",
      ).get(idempotencySettingKey) as {
        readonly value_json: string;
      } | undefined;
      if (prior) {
        const stored = parseCancellationIdempotencyRecord(prior.value_json);
        if (stored.requestHash !== requestHash) {
          throw executionError(
            409,
            "research_cancel_idempotency_conflict",
            "This cancellation key was already used for a different request.",
            "conflict",
          );
        }
        const replay = this.read(stored.runId);
        return {
          run: replay,
          ...(stored.state === "reserved" && !isTerminalRunStatus(replay.status)
            ? { intent: this.durableCancellationIntent(stored.runId) }
            : {}),
        };
      }
      if (reason.length < 3 || reason.length > 1_000) {
        throw executionError(
          400,
          "research_cancel_reason_required",
          "Explain why this bounded Research run should stop.",
          "invalid_input",
        );
      }
      const context = runContext(this.#database, input.runId);
      if (context.campaign_owner !== input.actorId) {
        throw executionError(
          403,
          "research_campaign_owner_required",
          "Only the named human campaign owner may cancel this experiment.",
          "authorization_denied",
        );
      }
      const current = this.read(input.runId);
      const now = this.#clock().toISOString();
      if (isTerminalRunStatus(current.status)) {
        const completed: CancellationIdempotencyRecord = {
          schemaVersion:
            "ti-scale.research-cancellation-idempotency.v1",
          requestHash,
          runId: input.runId,
          state: "completed",
          terminalStatus: current.status,
          reservedAt: now,
          completedAt: now,
        };
        this.#database.prepare(`
          INSERT INTO settings (
            key, value_json, sensitivity, version, updated_by, updated_at
          ) VALUES (?, ?, 'private', 1, ?, ?)
        `).run(
          idempotencySettingKey,
          canonicalJson(completed as unknown as JsonValue),
          input.actorId,
          now,
        );
        return { run: current };
      }
      const existingIntent = this.durableCancellationIntent(input.runId);
      if (
        existingIntent
        && existingIntent.state === "reserved"
        && existingIntent.requestHash !== requestHash
      ) {
        throw executionError(
          409,
          "research_cancel_already_reserved",
          "A different durable cancellation request is already stopping this Research run.",
          "conflict",
          "Wait for the reserved cancellation to reach a terminal state, then refresh the run.",
        );
      }
      const intent: DurableCancellationIntent = existingIntent ?? {
        schemaVersion: "ti-scale.research-cancellation-intent.v1",
        requestHash,
        runId: input.runId,
        actorId: input.actorId,
        reason,
        promotionIdempotencyKey:
          `cancel-intent:${sha256(input.idempotencyKey)}`,
        state: "reserved",
        terminalStatus: null,
        reservedAt: now,
        completedAt: null,
      };
      if (!existingIntent) {
        this.#database.prepare(`
          INSERT INTO settings (
            key, value_json, sensitivity, version, updated_by, updated_at
          ) VALUES (?, ?, 'private', 1, ?, ?)
        `).run(
          cancellationIntentSettingKey(input.runId),
          canonicalJson(intent as unknown as JsonValue),
          input.actorId,
          now,
        );
      }
      const idempotency: CancellationIdempotencyRecord = {
        schemaVersion: "ti-scale.research-cancellation-idempotency.v1",
        requestHash,
        runId: input.runId,
        state: "reserved",
        terminalStatus: null,
        reservedAt: now,
        completedAt: null,
      };
      this.#database.prepare(`
        INSERT INTO settings (
          key, value_json, sensitivity, version, updated_by, updated_at
        ) VALUES (?, ?, 'private', 1, ?, ?)
      `).run(
        idempotencySettingKey,
        canonicalJson(idempotency as unknown as JsonValue),
        input.actorId,
        now,
      );
      if (current.status === "queued") {
        return {
          run: this.finalizeCancellation(context, intent, true),
        };
      }
      return { run: current, intent };
    });
  }

  private async executeReservedCancellation(
    intent: DurableCancellationIntent,
  ): Promise<ResearchExperimentRunRecord> {
    const context = runContext(this.#database, intent.runId);
    let cleanupVerified = true;
    try {
      const current = this.read(intent.runId);
      if (isTerminalRunStatus(current.status)) {
        return this.finalizeCancellation(context, intent, true);
      }
      const active = this.#activeWorkers.get(intent.runId);
      if (active) {
        cleanupVerified = await active.terminate();
      } else if (current.status === "running") {
        const admission = this.#database.prepare(`
          SELECT worker_process_id, worker_process_start_ticks
          FROM research_experiment_admissions
          WHERE experiment_run_id = ? AND status = 'running'
        `).get(intent.runId) as {
          readonly worker_process_id: number | null;
          readonly worker_process_start_ticks: string | null;
        } | undefined;
        cleanupVerified = Boolean(
          admission?.worker_process_id
          && admission.worker_process_start_ticks
          && await terminateExactProcessAndWait(
            admission.worker_process_id,
            admission.worker_process_start_ticks,
          ),
        );
      }
      const activeLab = this.#activeLabs.get(intent.runId);
      if (activeLab) {
        cleanupVerified = activeLab.dispose() && cleanupVerified;
      }
      return this.finalizeCancellation(
        context,
        intent,
        cleanupVerified,
      );
    } finally {
      this.#activeWorkers.delete(intent.runId);
      this.#activeLabs.delete(intent.runId);
    }
  }

  async cancel(
    input: CancelExperimentRunInput,
  ): Promise<ResearchExperimentRunRecord> {
    const reason = input.reason.trim();
    const reservation = this.reserveCancellation(input, reason);
    if (!reservation.intent || isTerminalRunStatus(reservation.run.status)) {
      return reservation.run;
    }
    return this.driveReservedCancellation(reservation.intent);
  }

  private driveReservedCancellation(
    intent: DurableCancellationIntent,
  ): Promise<ResearchExperimentRunRecord> {
    const priorTask = this.#activeCancellations.get(intent.runId);
    if (priorTask) return priorTask;
    this.#cancelRequested.add(intent.runId);
    let tracked!: Promise<ResearchExperimentRunRecord>;
    tracked = this.executeReservedCancellation(intent).finally(() => {
      if (this.#activeCancellations.get(intent.runId) === tracked) {
        this.#activeCancellations.delete(intent.runId);
      }
      this.#cancelRequested.delete(intent.runId);
      this.#activeWorkers.delete(intent.runId);
      this.#activeLabs.delete(intent.runId);
    });
    this.#activeCancellations.set(intent.runId, tracked);
    return tracked;
  }

  async cancelCampaign(
    input: CancelResearchCampaignInput,
  ): Promise<readonly ResearchExperimentRunRecord[]> {
    const owner = this.#database.prepare(`
      SELECT owner FROM research_campaigns WHERE id = ?
    `).get(input.campaignId) as { readonly owner: string } | undefined;
    if (!owner) {
      throw executionError(
        404,
        "research_campaign_not_found",
        "The requested Research campaign does not exist.",
        "not_found",
      );
    }
    if (owner.owner !== input.actorId) {
      throw executionError(
        403,
        "research_campaign_owner_required",
        "Only the named human campaign owner may cancel its active experiments.",
        "authorization_denied",
      );
    }
    const runs = this.#database.prepare(`
      SELECT run.id
      FROM experiment_runs run
      JOIN experiments experiment ON experiment.id = run.experiment_id
      WHERE experiment.campaign_id = ?
        AND run.status IN ('queued', 'running')
      ORDER BY run.created_at, run.id
    `).all(input.campaignId) as ExistingRunRow[];
    const results: ResearchExperimentRunRecord[] = [];
    for (const { id } of runs) {
      results.push(await this.cancel({
        runId: id,
        actorId: input.actorId,
        reason: input.reason,
        idempotencyKey: `${input.idempotencyKey}:${sha256(id)}`,
      }));
    }
    return Object.freeze(results);
  }

  private schedule(runId: string): void {
    if (this.stopping || this.#activeTasks.has(runId)) return;
    const task = this.queue
      .then(() => this.process(runId))
      .catch(async (error: unknown) => {
        let cleanupVerified = true;
        const worker = this.#activeWorkers.get(runId);
        if (worker) {
          cleanupVerified = await worker.terminate();
          this.#activeWorkers.delete(runId);
        }
        try {
          this.failWithoutJoinedContext(runId, error, cleanupVerified);
        } catch (terminalError) {
          console.error(
            `[ti-scale:research] Could not retain unexpected terminal state for ${runId}.`,
            terminalError,
          );
        }
      })
      .finally(() => {
        this.#activeTasks.delete(runId);
      });
    this.queue = task;
    this.#activeTasks.set(runId, task);
  }

  private admit(
    context: RunContextRow,
    validated: ValidatedRunContext,
    lab: PreparedLabEnvironment,
    worker: PreparedExperimentWorker,
  ): {
    readonly admissionId: string;
    readonly admissionHash: string;
  } {
    if (this.cancellationPending(context.run_id)) {
      throw new Error(
        "Research cancellation was durably reserved before admission.",
      );
    }
    if (!worker.isAlive()) {
      throw new Error("The challenged Research worker exited before admission.");
    }
    if (
      worker.subject.launcherIdentityHash
        !== context.execution_environment_identity_hash
      || worker.subject.workerSourceSha256
        !== isolatedExperimentWorkerSourceSha256()
      || hashCanonical(validated.candidate as unknown as JsonValue)
        !== context.candidate_bundle_hash
    ) {
      throw new Error(
        "The challenged worker or candidate bytes differ from the immutable execution setup.",
      );
    }
    const bindings: ResearchExecutionBindings = {
      experimentId: context.experiment_id,
      scenarioId: context.scenario_id,
      benchmarkSnapshotHash: context.benchmark_snapshot_hash,
      evaluatorHash: context.evaluator_hash,
      toolManifestHash: context.tool_manifest_hash,
      resetGeneration: lab.resetGeneration,
    };
    for (const [kind, receipt] of [
      ["lab", lab.receipt],
      ["worker", worker.receipt],
    ] as const) {
      const verified = this.#boundary.keyring.verify(receipt, {
        ...bindings,
        kind,
      });
      if (!verified.valid) {
        throw new Error(
          `Research ${kind} receipt failed atomic admission: ${verified.reasons.join(",")}`,
        );
      }
    }
    const admissionId = `research_admission_${randomUUID()}`;
    const admittedAt = this.#clock().toISOString();
    const trustedScenario = validated.setup.scenarios.find(
      ({ id }) => id === context.scenario_id,
    )!;
    const plan: PlannedExperiment = {
      id: context.experiment_id,
      campaignId: validated.catalogId,
      charterId: context.charter_id,
      charterHash: context.charter_hash,
      dimensionId: validated.setup.dimensionId,
      baselineStrategyId: context.baseline_strategy_id,
      baselineStrategyHash: context.baseline_bundle_hash,
      candidateStrategyId: context.candidate_strategy_id,
      candidate: validated.candidate,
      candidateStrategyHash: context.candidate_bundle_hash,
      patch: validated.patch,
      patchHash: context.patch_hash,
      hypothesis: validated.setup.hypothesis,
      expectedMechanism: validated.setup.hypothesis,
      benchmarkSnapshotHash: context.benchmark_snapshot_hash,
      evaluatorHash: context.evaluator_hash,
      status: "queued",
      estimatedCost: {
        wallClockMs: 30_000,
        publicLlmTokens: 0,
        estimatedCost: 0,
        toolCalls: 0,
      },
      createdBy: context.campaign_owner,
      createdAt: admittedAt,
      executionBoundary: {
        disposableLocalLabRequired: true,
        publicProviderMayExecute: false,
        liveClientTargetAllowed: false,
        candidateMayModifyEvaluator: false,
        candidateMayAutoDeploy: false,
        hiddenHoldoutDetailsIncluded: false,
      },
    };
    const executionAuthorization = this.#executionPolicy.authorize({
      plan,
      scenario: {
        id: trustedScenario.id,
        familyId: validated.setup.family.id,
        split: trustedScenario.split,
        name: trustedScenario.name,
        scenarioHash: trustedScenario.scenarioHash,
        environmentDigest: trustedScenario.environmentDigest,
        groundTruthRef: trustedScenario.groundTruthRef,
      },
      context: {
        environmentId: lab.workspacePath,
        environmentDigest: context.scenario_environment_digest,
        targetClass: "synthetic_fixture",
        authorizationScope: "benchmark_scenario_only",
        resetMode: "recreate",
        resetReceiptHash: hashCanonical(
          lab.receipt as unknown as JsonValue,
        ),
        workerProcessKind: "isolated_experiment_worker",
        productionCredentialMounts: 0,
        outboundNetworkPolicy: "disabled",
        publicProviderHasExecutionAuthority: false,
        candidateCanMutateHarness: false,
        benchmarkSnapshotHash: context.benchmark_snapshot_hash,
        evaluatorHash: context.evaluator_hash,
        toolManifestHash: context.tool_manifest_hash,
      },
      trustedToolManifestHash: context.tool_manifest_hash,
      authorizedAt: admittedAt,
    });
    const executionAuthorizationHash = hashCanonical(
      executionAuthorization as unknown as JsonValue,
    );
    const seedHash = sha256(context.seed);
    const admissionPayload = {
      schemaVersion: "ti-scale.research-admission.v1",
      admissionId,
      runId: context.run_id,
      ...bindings,
      seed: context.seed,
      seedHash,
      charterId: context.charter_id,
      charterHash: context.charter_hash,
      baselineStrategyId: context.baseline_strategy_id,
      baselineStrategyHash: context.baseline_bundle_hash,
      candidateStrategyId: context.candidate_strategy_id,
      candidateStrategyHash: context.candidate_bundle_hash,
      executionAuthorization,
      executionAuthorizationHash,
      labReceiptId: lab.receipt.receiptId,
      workerReceiptId: worker.receipt.receiptId,
      workerProcessId: worker.processId,
      workerProcessStartTicks: worker.subject.processStartTicks,
      admittedAt,
    } as unknown as JsonValue;
    const admissionHash = hashCanonical(admissionPayload);
    const admissionSignature =
      this.#boundary.keyring.createAdmissionSignature(admissionPayload);
    inImmediateTransaction(this.#database, () => {
      const current = runContext(this.#database, context.run_id);
      validateRunContext(current, this.#boundary, this.#privateHoldout);
      if (
        this.cancellationPending(context.run_id)
        ||
        current.run_status !== "queued"
        || current.experiment_status
          !== stageStartStatus(context.scenario_split)
        || current.experiment_updated_at !== context.experiment_updated_at
        || current.scenario_environment_digest
          !== context.scenario_environment_digest
        || current.benchmark_snapshot_hash !== context.benchmark_snapshot_hash
        || current.evaluator_hash !== context.evaluator_hash
        || current.tool_manifest_hash !== context.tool_manifest_hash
        || immutableExecutionContextFingerprint(current)
          !== immutableExecutionContextFingerprint(context)
        || worker.subject.launcherIdentityHash
          !== current.execution_environment_identity_hash
        || !worker.isAlive()
      ) {
        throw new Error("Research execution state changed before atomic admission.");
      }
      // Reverify after the database reservation and immediately before the
      // challenged process receives any job.
      for (const [kind, receipt] of [
        ["lab", lab.receipt],
        ["worker", worker.receipt],
      ] as const) {
        const verified = this.#boundary.keyring.verify(receipt, {
          ...bindings,
          kind,
        });
        if (!verified.valid) {
          throw new Error(
            `Research ${kind} receipt became invalid before spawn: ${verified.reasons.join(",")}`,
          );
        }
      }
      persistReceipt(this.#database, lab.receipt);
      persistReceipt(this.#database, worker.receipt);
      this.#database.prepare(`
        INSERT INTO research_experiment_admissions (
          id, experiment_run_id, experiment_id, scenario_id,
          lab_receipt_id, worker_receipt_id, reset_generation,
          admission_hash, admission_signature, status,
          admitted_at, started_at, ended_at, terminal_result_hash,
          charter_id, charter_hash,
          baseline_strategy_id, baseline_strategy_hash,
          candidate_strategy_id, candidate_strategy_hash,
          seed_hash, execution_authorization_hash,
          admission_payload_json, worker_process_id,
          worker_process_start_ticks
        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, 'admitted', ?, NULL, NULL, NULL,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
      `).run(
        admissionId,
        context.run_id,
        context.experiment_id,
        context.scenario_id,
        lab.receipt.receiptId,
        worker.receipt.receiptId,
        lab.resetGeneration,
        admissionHash,
        admissionSignature,
        admittedAt,
        context.charter_id,
        context.charter_hash,
        context.baseline_strategy_id,
        context.baseline_bundle_hash,
        context.candidate_strategy_id,
        context.candidate_bundle_hash,
        seedHash,
        executionAuthorizationHash,
        canonicalJson(admissionPayload),
        worker.processId,
        worker.subject.processStartTicks,
      );
      for (const receipt of [lab.receipt, worker.receipt]) {
        const update = this.#database.prepare(`
          UPDATE research_execution_receipts
          SET consumed_at = ?, consumed_by_run_id = ?
          WHERE id = ? AND consumed_at IS NULL
        `).run(admittedAt, context.run_id, receipt.receiptId);
        if (update.changes !== 1) {
          throw new Error("Research execution receipt was already consumed.");
        }
      }
      this.#database.prepare(`
        UPDATE research_experiment_admissions
        SET status = 'running', started_at = ?
        WHERE id = ? AND status = 'admitted'
      `).run(admittedAt, admissionId);
      this.#database.prepare(`
        UPDATE experiment_runs
        SET status = 'running', worker_id = ?, started_at = ?
        WHERE id = ? AND status = 'queued'
      `).run(
        worker.receipt.subjectIdentityHash,
        admittedAt,
        context.run_id,
      );
      this.#database.prepare(`
        UPDATE experiments
        SET status = 'running', updated_at = ?
        WHERE id = ? AND status = ?
      `).run(
        admittedAt,
        context.experiment_id,
        stageStartStatus(context.scenario_split),
      );
      this.#database.prepare(`
        UPDATE strategy_versions
        SET status = 'running'
        WHERE id = ? AND status = ?
      `).run(
        context.candidate_strategy_id,
        stageStartStatus(context.scenario_split),
      );
      appendEvent(this.#database, {
        experimentId: context.experiment_id,
        runId: context.run_id,
        eventType: "experiment_run.admitted",
        summary: "Fresh one-use lab and worker receipts admitted the exact synthetic benchmark process.",
        payload: {
          admissionId,
          admissionHash,
          labReceiptId: lab.receipt.receiptId,
          workerReceiptId: worker.receipt.receiptId,
          resetGeneration: lab.resetGeneration,
          executionAuthorizationId: executionAuthorization.id,
          executionAuthorizationHash,
          candidateStrategyHash: context.candidate_bundle_hash,
          seedHash,
        },
        occurredAt: admittedAt,
      });
    });
    return { admissionId, admissionHash };
  }

  private complete(
    context: RunContextRow,
    admissionId: string,
    result: ExperimentWorkerResult,
  ): void {
    const endedAt = this.#clock().toISOString();
    const currentContext = runContext(this.#database, context.run_id);
    const validated = validateRunContext(
      currentContext,
      this.#boundary,
      this.#privateHoldout,
    );
    if (
      currentContext.run_status !== "running"
      || currentContext.experiment_status !== "running"
      || immutableExecutionContextFingerprint(currentContext)
        !== immutableExecutionContextFingerprint(context)
      || result.candidateHash !== context.candidate_bundle_hash
      || !HASH.test(result.fixtureHash)
      || result.decision.kind === "self_test"
    ) {
      throw new Error(
        "Research result or canonical bindings changed before trusted local evaluation.",
      );
    }
    const localScenario: LocalSyntheticScenarioEvaluation =
      context.scenario_split === "hidden_holdout"
        ? this.#privateHoldout!.evaluate({
            scenarioId: context.scenario_id,
            candidate: validated.candidate,
            workerDecision: result.decision,
            fixtureIntegrity: result.fixtureIntegrity,
            fixtureHash: result.fixtureHash,
            admissionHash: result.admissionHash,
          })
        : evaluateSyntheticResearchDecision({
            scenarioId: context.scenario_id,
            candidate: validated.candidate,
            workerDecision: result.decision,
            fixtureIntegrity: result.fixtureIntegrity,
            fixtureHash: result.fixtureHash,
            admissionHash: result.admissionHash,
          });
    const expectedWorkerEventHash = hashCanonical({
      experimentId: context.experiment_id,
      scenarioId: context.scenario_id,
      candidateHash: context.candidate_bundle_hash,
      seedHash: sha256(context.seed),
      decision: result.decision,
    } as unknown as JsonValue);
    const expectedWorkerEvidenceHash = hashCanonical({
      fixtureHash: result.fixtureHash,
      admissionHash: result.admissionHash,
      workerSourceSha256: isolatedExperimentWorkerSourceSha256(),
    } as unknown as JsonValue);
    const gateSignals = new Set(localScenario.gateSignals);
    if (
      result.eventHash !== expectedWorkerEventHash
      || result.evidenceHash !== expectedWorkerEvidenceHash
    ) gateSignals.add("integrity_receipt_mismatch");
    const harness = createBuiltInResearchEvaluationHarness(validated.setup);
    const evaluation = harness.evaluate(context.scenario_split, [{
      scenarioId: context.scenario_id,
      split: context.scenario_split,
      source: "local_evaluator",
      metrics: localScenario.metrics,
      gateSignals: [...gateSignals],
      eventHash: localScenario.eventHash,
      evidenceHash: localScenario.evidenceHash,
    }]);
    const resultHash = hashCanonical({
      workerResult: result,
      localEvaluation: evaluation,
    } as unknown as JsonValue);
    const metricsHash = hashCanonical(
      evaluation.metrics as unknown as JsonValue,
    );
    const action = evaluation.disqualified
      ? stageFailAction(context.scenario_split)
      : stagePassAction(context.scenario_split);
    const receipt = this.#integrityAuthority.createReceipt({
      experimentId: context.experiment_id,
      charterHash: context.charter_hash,
      strategyHashes: {
        baseline: context.baseline_bundle_hash,
        candidate: context.candidate_bundle_hash,
      },
      evaluatorVersion: context.evaluator_version,
      evaluatorHash: context.evaluator_hash,
      benchmarkSnapshotHash: context.benchmark_snapshot_hash,
      containerImageDigest: "not_applicable:local_bwrap",
      executionEnvironment: {
        kind: "local_bwrap",
        identityHash: context.execution_environment_identity_hash,
      },
      toolManifestHash: context.tool_manifest_hash,
      providerModel: null,
      contextPackIds: [context.context_pack_id],
      randomSeeds: [context.seed],
      eventHash: evaluation.eventSetHash,
      evidenceHash: evaluation.evidenceSetHash,
      metricsHash,
      exposureReceiptIds: [],
      evaluationStage: context.scenario_split,
      evaluationAction: action,
      evaluationResult: evaluation.disqualified ? "fail" : "pass",
      evaluationAttemptId: context.run_id,
      hardGateFailures: evaluation.hardGateFailures,
      signedAt: endedAt,
    });
    inImmediateTransaction(this.#database, () => {
      const current = this.read(context.run_id);
      if (current.status !== "running") {
        throw new Error("Research experiment run is no longer running.");
      }
      const canonical = runContext(this.#database, context.run_id);
      if (
        canonical.run_status !== "running"
        || immutableExecutionContextFingerprint(canonical)
          !== immutableExecutionContextFingerprint(context)
      ) {
        throw new Error(
          "Research execution bindings changed before the terminal evaluator transaction.",
        );
      }
      const promotions = new ResearchPromotionLifecycleRepository(
        this.#database,
        this.#integrityAuthority,
        this.#clock,
      );
      promotions.persistIntegrityReceipt(receipt);
      const lifecycle = promotions.get(context.experiment_id);
      promotions.applyLocalTransition({
        experimentId: context.experiment_id,
        expectedVersion: lifecycle.version,
        action,
        actorId: "ti-scale:local-synthetic-evaluator",
        rationale: evaluation.disqualified
          ? `The trusted local evaluator rejected the ${context.scenario_split.replace("_", " ")} result because one or more hard gates failed.`
          : `The trusted local evaluator recomputed the ${context.scenario_split.replace("_", " ")} metrics from typed worker decisions.`,
        evidenceRefs: [
          `experiment-run:${context.run_id}`,
          `integrity-receipt:${receipt.id}`,
          `benchmark-scenario:${safeScenarioReference(context)}`,
        ],
        hardGateFailures: evaluation.hardGateFailures,
        integrityReceiptId: receipt.id,
      });
      const insertMetric = this.#database.prepare(`
        INSERT INTO experiment_metrics (
          id, experiment_run_id, metric_name, metric_value, unit,
          direction, authoritative, evaluator_version, computed_at
        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
      `);
      for (const metric of evaluation.metrics) {
        insertMetric.run(
          `research_metric_${randomUUID()}`,
          context.run_id,
          metric.name,
          metric.value,
          metric.direction === "gate" ? "gate" : "ratio",
          metric.direction,
          context.evaluator_version,
          endedAt,
        );
      }
      const terminalRunStatus = evaluation.disqualified
        ? context.scenario_split === "development"
          ? "early_aborted"
          : "failed"
        : "completed";
      const terminalAdmissionStatus = evaluation.disqualified
        ? "failed"
        : "completed";
      const admissionUpdate = this.#database.prepare(`
        UPDATE research_experiment_admissions
        SET status = ?, ended_at = ?, terminal_result_hash = ?
        WHERE id = ? AND status = 'running'
      `).run(
        terminalAdmissionStatus,
        endedAt,
        resultHash,
        admissionId,
      );
      if (admissionUpdate.changes !== 1) {
        throw new Error(
          "Research terminal result lost its exact running admission.",
        );
      }
      const runUpdate = this.#database.prepare(`
        UPDATE experiment_runs
        SET status = ?, ended_at = ?
        WHERE id = ? AND status = 'running'
      `).run(terminalRunStatus, endedAt, context.run_id);
      if (runUpdate.changes !== 1) {
        throw new Error(
          "Research terminal evaluator could not commit the exact running run.",
        );
      }
      const nextStatus = stageTerminalStatus(
        context.scenario_split,
        !evaluation.disqualified,
      );
      if (
        context.scenario_split === "development"
        && !evaluation.disqualified
      ) {
        // A passing development result deliberately leaves the promotion
        // lifecycle in `running` with developmentPassed=true. The execution
        // records use `benchmarked` as the durable idle state from which the
        // next validation admission is allowed.
        const experimentUpdate = this.#database.prepare(`
          UPDATE experiments
          SET status = 'benchmarked', updated_at = ?
          WHERE id = ? AND status = 'running'
        `).run(endedAt, context.experiment_id);
        const candidateUpdate = this.#database.prepare(`
          UPDATE strategy_versions
          SET status = 'benchmarked'
          WHERE id = ? AND status = 'running'
        `).run(context.candidate_strategy_id);
        if (
          experimentUpdate.changes !== 1
          || candidateUpdate.changes !== 1
        ) {
          throw new Error(
            "Research terminal evaluator could not park the passed development stage.",
          );
        }
      } else {
        // Validation/holdout transitions and every local rejection already
        // project their exact terminal state through the lifecycle repository.
        const projected = this.#database.prepare(`
          SELECT experiment.status AS experiment_status,
            candidate.status AS candidate_status
          FROM experiments experiment
          JOIN strategy_versions candidate
            ON candidate.id = experiment.candidate_strategy_id
          WHERE experiment.id = ?
        `).get(context.experiment_id) as {
          readonly experiment_status: string;
          readonly candidate_status: string;
        } | undefined;
        if (
          projected?.experiment_status !== nextStatus
          || projected.candidate_status !== nextStatus
        ) {
          throw new Error(
            "Research promotion lifecycle projected an unexpected terminal stage.",
          );
        }
      }
      appendEvent(this.#database, {
        experimentId: context.experiment_id,
        runId: context.run_id,
        eventType: evaluation.disqualified
          ? context.scenario_split === "development"
            ? "experiment_run.early_aborted"
            : "experiment_run.failed"
          : "experiment_run.completed",
        summary: evaluation.disqualified
          ? `The trusted local evaluator rejected the synthetic ${context.scenario_split.replace("_", " ")} result.`
          : `The trusted local evaluator completed the synthetic ${context.scenario_split.replace("_", " ")} result.`,
        payload: {
          admissionId,
          resultHash,
          integrityReceiptId: receipt.id,
          eventHash: evaluation.eventSetHash,
          evidenceHash: evaluation.evidenceSetHash,
          metrics: evaluation.metrics,
          hardGateFailures: evaluation.hardGateFailures,
          stage: context.scenario_split,
          scenarioId: safeScenarioReference(context),
          privateHoldout: this.#privateHoldout
            ? "trusted_descriptor_bound"
            : "operator_descriptor_required",
          promotionReady:
            context.scenario_split === "hidden_holdout"
            && !evaluation.disqualified,
        } as unknown as JsonValue,
        occurredAt: endedAt,
      });
    });
  }

  private fail(
    context: RunContextRow,
    error: unknown,
    cleanupVerified: boolean,
  ): void {
    const endedAt = this.#clock().toISOString();
    const errorMessage = error instanceof Error
      ? error.message
      : "Unknown Research execution error.";
    const humanReason = cleanupVerified
      ? `The bounded local Research run failed: ${errorMessage}`
      : "The bounded Research worker or fixture did not prove complete cleanup.";
    const gateCode = cleanupVerified
      ? "integrity_receipt_mismatch"
      : "orphaned_process";
    const terminalResultHash = hashCanonical({
      runId: context.run_id,
      outcome: "failed",
      cleanupVerified,
      gateCode,
      humanReason,
      endedAt,
    } as unknown as JsonValue);
    inImmediateTransaction(this.#database, () => {
      const current = this.read(context.run_id);
      if (["completed", "failed", "cancelled", "early_aborted"].includes(current.status)) {
        return;
      }
      if (current.status === "running") {
        const admission = this.#database.prepare(`
          SELECT id, status
          FROM research_experiment_admissions
          WHERE experiment_run_id = ?
        `).get(context.run_id) as {
          readonly id: string;
          readonly status: string;
        } | undefined;
        if (!admission || admission.status !== "running") {
          throw new Error(
            "Running Research failure lacks its exact running admission.",
          );
        }
        this.#database.prepare(`
          UPDATE research_experiment_admissions
          SET status = 'failed', ended_at = ?, terminal_result_hash = ?
          WHERE id = ? AND status = 'running'
        `).run(endedAt, terminalResultHash, admission.id);
        const hardGateFailures = cleanupVerified
          ? ["integrity_receipt_mismatch"] as const
          : ["integrity_receipt_mismatch", "orphaned_process"] as const;
        const failureEventHash = hashCanonical({
          runId: context.run_id,
          admissionId: admission.id,
          outcome: "failed",
          humanReason,
        } as unknown as JsonValue);
        const failureEvidenceHash = hashCanonical({
          terminalResultHash,
          cleanupVerified,
          hardGateFailures,
        } as unknown as JsonValue);
        const failureReceipt = this.#integrityAuthority.createReceipt({
          experimentId: context.experiment_id,
          charterHash: context.charter_hash,
          strategyHashes: {
            baseline: context.baseline_bundle_hash,
            candidate: context.candidate_bundle_hash,
          },
          evaluatorVersion: context.evaluator_version,
          evaluatorHash: context.evaluator_hash,
          benchmarkSnapshotHash: context.benchmark_snapshot_hash,
          containerImageDigest: "not_applicable:local_bwrap",
          executionEnvironment: {
            kind: "local_bwrap",
            identityHash: context.execution_environment_identity_hash,
          },
          toolManifestHash: context.tool_manifest_hash,
          providerModel: null,
          contextPackIds: [context.context_pack_id],
          randomSeeds: [context.seed],
          eventHash: failureEventHash,
          evidenceHash: failureEvidenceHash,
          metricsHash: hashCanonical([]),
          exposureReceiptIds: [],
          evaluationStage: context.scenario_split,
          evaluationAction: stageFailAction(context.scenario_split),
          evaluationResult: "fail",
          evaluationAttemptId: context.run_id,
          hardGateFailures,
          signedAt: endedAt,
        });
        const promotions = new ResearchPromotionLifecycleRepository(
          this.#database,
          this.#integrityAuthority,
          this.#clock,
        );
        let lifecycle = promotions.get(context.experiment_id);
        if (
          context.scenario_split === "development"
          && lifecycle.state === "queued"
        ) {
          lifecycle = promotions.applyLocalTransition({
            experimentId: context.experiment_id,
            expectedVersion: lifecycle.version,
            action: "start_benchmark",
            actorId: "ti-scale:local-research-policy",
            rationale:
              "The exact signed local-bwrap admission started this development attempt before its terminal execution failure.",
            evidenceRefs: [
              `research-admission:${admission.id}`,
              `experiment-run:${context.run_id}`,
            ],
          });
        }
        const requiredLifecycleState = context.scenario_split === "hidden_holdout"
          ? "benchmarked"
          : "running";
        if (lifecycle.state !== requiredLifecycleState) {
          throw new Error(
            "A running Research failure is inconsistent with its promotion lifecycle.",
          );
        }
        promotions.persistIntegrityReceipt(failureReceipt);
        promotions.applyLocalTransition({
          experimentId: context.experiment_id,
          expectedVersion: lifecycle.version,
          action: stageFailAction(context.scenario_split),
          actorId: "ti-scale:local-synthetic-evaluator",
          rationale:
            `The local evaluator rejected this ${context.scenario_split.replace("_", " ")} attempt because it did not produce a complete integrity-verifiable result.`,
          evidenceRefs: [
            `experiment-run:${context.run_id}`,
            `integrity-receipt:${failureReceipt.id}`,
            `research-admission:${admission.id}`,
          ],
          hardGateFailures,
          integrityReceiptId: failureReceipt.id,
        });
      }
      this.#database.prepare(`
        UPDATE experiment_runs
        SET status = 'failed', ended_at = ?
        WHERE id = ? AND status IN ('queued', 'running')
      `).run(endedAt, context.run_id);
      this.#database.prepare(`
        UPDATE experiments
        SET status = ?, updated_at = ?
        WHERE id = ? AND status IN ('queued', 'running', 'benchmarked')
      `).run(
        stageTerminalStatus(context.scenario_split, false),
        endedAt,
        context.experiment_id,
      );
      this.#database.prepare(`
        UPDATE strategy_versions
        SET status = ?
        WHERE id = ? AND status IN ('queued', 'running', 'benchmarked')
      `).run(
        stageTerminalStatus(context.scenario_split, false),
        context.candidate_strategy_id,
      );
      this.#database.prepare(`
        INSERT INTO experiment_failures (
          id, experiment_id, experiment_run_id, gate_code, category,
          human_reason, evidence_refs_json, terminal, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, '[]', 1, ?)
      `).run(
        `research_failure_${randomUUID()}`,
        context.experiment_id,
        context.run_id,
        gateCode,
        cleanupVerified ? "execution_boundary" : "orphan_cleanup",
        humanReason,
        endedAt,
      );
      appendEvent(this.#database, {
        experimentId: context.experiment_id,
        runId: context.run_id,
        eventType: "experiment_run.failed",
        summary: humanReason,
        payload: {
          gateCode,
          cleanupVerified,
          terminalResultHash,
          stage: context.scenario_split,
          scenarioId: safeScenarioReference(context),
        },
        occurredAt: endedAt,
      });
    });
  }

  /**
   * Last-resort terminalization for a queued run whose joined immutable
   * context cannot be reconstructed. This path deliberately uses only the
   * minimum parent identities required to retain the failure; it never
   * fabricates evaluator metrics or a promotion result.
   */
  private failWithoutJoinedContext(
    runId: string,
    error: unknown,
    cleanupVerified: boolean,
  ): void {
    const joined = this.#database.prepare(`
      SELECT
        run.status AS run_status,
        experiment.id AS experiment_id,
        experiment.candidate_strategy_id,
        scenario.split AS scenario_split
      FROM experiment_runs run
      JOIN experiments experiment ON experiment.id = run.experiment_id
      JOIN benchmark_scenarios scenario ON scenario.id = run.scenario_id
      WHERE run.id = ?
    `).get(runId) as {
      readonly run_status: ResearchExperimentRunRecord["status"];
      readonly experiment_id: string;
      readonly candidate_strategy_id: string;
      readonly scenario_split: ExecutableResearchStage;
    } | undefined;
    if (
      !joined
      || ["completed", "failed", "cancelled", "early_aborted"].includes(
        joined.run_status,
      )
    ) return;
    const endedAt = this.#clock().toISOString();
    const message = error instanceof Error
      ? error.message
      : "Unknown Research execution error.";
    const humanReason = cleanupVerified
      ? `The bounded local Research run failed before its complete immutable context could be reconstructed: ${message}`
      : "The bounded Research run lost its immutable context and worker cleanup could not be proven.";
    const gateCode = cleanupVerified ? "integrity_receipt_mismatch" : "orphaned_process";
    const terminalResultHash = hashCanonical({
      runId,
      outcome: "failed",
      cleanupVerified,
      gateCode,
      humanReason,
      endedAt,
    } as unknown as JsonValue);
    inImmediateTransaction(this.#database, () => {
      const current = this.read(runId);
      if (
        ["completed", "failed", "cancelled", "early_aborted"].includes(
          current.status,
        )
      ) return;
      if (current.status === "running") {
        const admissionUpdate = this.#database.prepare(`
          UPDATE research_experiment_admissions
          SET status = 'failed', ended_at = ?, terminal_result_hash = ?
          WHERE experiment_run_id = ? AND status = 'running'
        `).run(endedAt, terminalResultHash, runId);
        if (admissionUpdate.changes !== 1) {
          throw new Error(
            "A running Research run cannot be terminalized without its exact admission.",
          );
        }
      }
      const runUpdate = this.#database.prepare(`
        UPDATE experiment_runs
        SET status = 'failed', ended_at = ?
        WHERE id = ? AND status IN ('queued', 'running')
      `).run(endedAt, runId);
      if (runUpdate.changes !== 1) {
        throw new Error(
          "The Research runner could not retain its unexpected terminal failure.",
        );
      }
      this.#database.prepare(`
        UPDATE experiments
        SET status = ?, updated_at = ?
        WHERE id = ? AND status IN ('queued', 'running', 'benchmarked')
      `).run(
        stageTerminalStatus(joined.scenario_split, false),
        endedAt,
        joined.experiment_id,
      );
      this.#database.prepare(`
        UPDATE strategy_versions
        SET status = ?
        WHERE id = ? AND status IN ('queued', 'running', 'benchmarked')
      `).run(
        stageTerminalStatus(joined.scenario_split, false),
        joined.candidate_strategy_id,
      );
      this.#database.prepare(`
        INSERT INTO experiment_failures (
          id, experiment_id, experiment_run_id, gate_code, category,
          human_reason, evidence_refs_json, terminal, created_at
        ) VALUES (?, ?, ?, ?, 'execution_integrity', ?, '[]', 1, ?)
      `).run(
        `research_failure_${randomUUID()}`,
        joined.experiment_id,
        runId,
        gateCode,
        humanReason,
        endedAt,
      );
      appendEvent(this.#database, {
        experimentId: joined.experiment_id,
        runId,
        eventType: "experiment_run.failed",
        summary: humanReason,
        payload: {
          gateCode,
          cleanupVerified,
          terminalResultHash,
          joinedContextAvailable: false,
          stage: joined.scenario_split,
        },
        occurredAt: endedAt,
      });
    });
  }

  private async process(runId: string): Promise<void> {
    if (this.stopping || this.cancellationPending(runId)) return;
    let context: RunContextRow;
    try {
      context = runContext(this.#database, runId);
    } catch (error) {
      this.failWithoutJoinedContext(runId, error, true);
      return;
    }
    if (context.run_status !== "queued") return;
    if (this.cancellationPending(runId)) return;
    if (
      context.experiment_status
        !== stageStartStatus(context.scenario_split)
      || context.scenario_active !== 1
      || context.scenario_family_id !== context.snapshot_family_id
      || !HASH.test(context.benchmark_snapshot_hash)
      || !HASH.test(context.evaluator_hash)
      || !HASH.test(context.tool_manifest_hash)
    ) {
      this.fail(
        context,
        new Error("The queued run lost its immutable benchmark binding."),
        true,
      );
      return;
    }
    let validated: ValidatedRunContext;
    try {
      validated = validateRunContext(
        context,
        this.#boundary,
        this.#privateHoldout,
      );
    } catch (error) {
      this.fail(context, error, true);
      return;
    }
    const fixture = context.scenario_split === "hidden_holdout"
      ? this.#privateHoldout?.fixtureFor({
          scenarioId: context.scenario_id,
          environmentDigest: context.scenario_environment_digest,
        })
      : this.#fixtures.fixtureFor({
          id: context.scenario_id,
          environmentDigest: context.scenario_environment_digest,
        });
    if (!fixture) {
      this.fail(
        context,
        new Error("No reviewed synthetic fixture matches this scenario digest."),
        true,
      );
      return;
    }
    let lab: PreparedLabEnvironment | undefined;
    let worker: PreparedExperimentWorker | undefined;
    let cleanupVerified = true;
    try {
      if (this.cancellationPending(runId)) return;
      lab = this.#boundary.labManager.prepare({
        experimentId: context.experiment_id,
        scenarioId: context.scenario_id,
        benchmarkSnapshotHash: context.benchmark_snapshot_hash,
        evaluatorHash: context.evaluator_hash,
        toolManifestHash: context.tool_manifest_hash,
        resetGeneration: context.benchmark_snapshot_hash,
        fixture,
      });
      this.#activeLabs.set(runId, lab);
      if (this.cancellationPending(runId)) {
        throw new Error(
          "Research cancellation was reserved after lab preparation.",
        );
      }
      worker = await this.#boundary.workerLauncher.prepare({
        experimentId: context.experiment_id,
        scenarioId: context.scenario_id,
        benchmarkSnapshotHash: context.benchmark_snapshot_hash,
        evaluatorHash: context.evaluator_hash,
        toolManifestHash: context.tool_manifest_hash,
        resetGeneration: lab.resetGeneration,
        lab,
      });
      this.#activeWorkers.set(runId, worker);
      if (this.cancellationPending(runId)) {
        throw new Error(
          "Research cancellation was reserved after worker preparation.",
        );
      }
      const admission = this.admit(context, validated, lab, worker);
      const promotions = new ResearchPromotionLifecycleRepository(
        this.#database,
        this.#integrityAuthority,
        this.#clock,
      );
      const lifecycle = promotions.get(context.experiment_id);
      if (
        context.scenario_split === "development"
        && lifecycle.state !== "running"
      ) {
        promotions.applyLocalTransition({
          experimentId: context.experiment_id,
          expectedVersion: lifecycle.version,
          action: "start_benchmark",
          actorId: "ti-scale:local-research-policy",
          rationale:
            "The exact signed local-bwrap admission is running the approved synthetic development fixture.",
          evidenceRefs: [
            `research-admission:${admission.admissionId}`,
            `benchmark-scenario:${context.scenario_id}`,
          ],
        });
      }
      if (
        context.scenario_split === "validation"
        && (
          lifecycle.state !== "running"
          || !lifecycle.milestones.developmentPassed
        )
      ) {
        throw new Error(
          "Validation execution lost its completed development milestone.",
        );
      }
      if (
        context.scenario_split === "hidden_holdout"
        && (
          lifecycle.state !== "benchmarked"
          || !lifecycle.milestones.validationPassed
        )
      ) {
        throw new Error(
          "Hidden-holdout execution lost its completed validation milestone.",
        );
      }
      if (this.cancellationPending(runId)) {
        throw new Error(
          "Research cancellation was reserved before worker execution.",
        );
      }
      const candidate = validated.candidate as unknown as JsonValue;
      const result = await worker.execute({
        ...admission,
        experimentId: context.experiment_id,
        scenarioId: context.scenario_id,
        seed: context.seed,
        candidate,
      });
      if (this.cancellationPending(runId)) {
        throw new Error(
          "Research cancellation was reserved before result evaluation.",
        );
      }
      const workerCleaned = await worker.terminate();
      this.#activeWorkers.delete(runId);
      worker = undefined;
      const labCleaned = lab.dispose();
      this.#activeLabs.delete(runId);
      lab = undefined;
      cleanupVerified = workerCleaned && labCleaned;
      if (!cleanupVerified) {
        throw new Error("Research execution cleanup proof failed.");
      }
      this.complete(context, admission.admissionId, result);
    } catch (error) {
      if (worker) {
        cleanupVerified = (await worker.terminate()) && cleanupVerified;
        this.#activeWorkers.delete(runId);
      }
      if (lab) {
        cleanupVerified = lab.dispose() && cleanupVerified;
        this.#activeLabs.delete(runId);
      }
      if (this.cancellationPending(runId)) return;
      this.fail(context, error, cleanupVerified);
    } finally {
      this.#activeWorkers.delete(runId);
      this.#activeLabs.delete(runId);
    }
  }

  private recoverInterruptedRuns(): void {
    const interrupted = this.#database.prepare(`
      SELECT
        run.id,
        admission.worker_process_id,
        admission.worker_process_start_ticks
      FROM experiment_runs run
      LEFT JOIN research_experiment_admissions admission
        ON admission.experiment_run_id = run.id
       AND admission.status = 'running'
      WHERE run.status = 'running'
    `).all() as Array<{
      readonly id: string;
      readonly worker_process_id: number | null;
      readonly worker_process_start_ticks: string | null;
    }>;
    for (const interruptedRun of interrupted) {
      const { id } = interruptedRun;
      const context = runContext(this.#database, id);
      const cancellation = this.durableCancellationIntent(id);
      if (cancellation?.state === "reserved") {
        void this.driveReservedCancellation(cancellation).catch((error) => {
          console.error(
            `[ti-scale:research] Could not resume durable cancellation for ${id}.`,
            error,
          );
        });
      } else {
        const cleanupVerified = Boolean(
          interruptedRun.worker_process_id
          && interruptedRun.worker_process_start_ticks
          && (
            processStartTicks(interruptedRun.worker_process_id)
              !== interruptedRun.worker_process_start_ticks
            || terminateExactProcess(
              interruptedRun.worker_process_id,
              interruptedRun.worker_process_start_ticks,
            )
          ),
        );
        this.fail(
          context,
          new Error("The process restarted before the isolated worker reached a terminal result."),
          cleanupVerified,
        );
      }
    }
  }

  private recoverQueuedCancellations(): void {
    const queued = this.#database.prepare(`
      SELECT id FROM experiment_runs
      WHERE status = 'queued'
      ORDER BY created_at, id
    `).all() as ExistingRunRow[];
    for (const { id } of queued) {
      const cancellation = this.durableCancellationIntent(id);
      if (cancellation?.state !== "reserved") continue;
      this.finalizeCancellation(
        runContext(this.#database, id),
        cancellation,
        true,
      );
    }
  }

  start(): void {
    if (this.stopping) throw new Error("Research ExperimentRunner is stopping.");
    if (this.started) return;
    this.recoverQueuedCancellations();
    this.recoverInterruptedRuns();
    this.started = true;
    const queued = this.#database.prepare(`
      SELECT id FROM experiment_runs WHERE status = 'queued' ORDER BY created_at, id
    `).all() as ExistingRunRow[];
    for (const { id } of queued) this.schedule(id);
  }

  beginStop(): void {
    if (this.stopping) return;
    this.stopping = true;
    this.started = false;
    for (const worker of this.#activeWorkers.values()) {
      void worker.terminate();
    }
  }

  async stop(): Promise<void> {
    this.beginStop();
    await Promise.allSettled([...this.#activeCancellations.values()]);
    await Promise.allSettled([...this.#activeTasks.values()]);
    await Promise.all(
      [...this.#activeWorkers.values()].map((worker) => worker.terminate()),
    );
    this.#activeWorkers.clear();
    for (const lab of this.#activeLabs.values()) lab.dispose();
    this.#activeLabs.clear();
    this.#activeCancellations.clear();
    this.#cancelRequested.clear();
  }
}

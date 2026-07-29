import { randomUUID } from "node:crypto";
import { createDatabaseConnection } from "../../../server/db";
import { canonicalJson } from "../../../server/missions/canonical";
import {
  DEFAULT_RESEARCH_BUDGETS,
} from "../../../server/research/ResearchLabRepository";
import {
  IntegrityAuthority,
  LlmExposurePolicy,
  ResearchPromotionLifecycleRepository,
  type ExperimentIntegrityPayload,
  type HumanResearchPromotionAction,
  type LocalResearchPromotionAction,
} from "../../../server/research";
import {
  DEFAULT_STRATEGY_BUNDLE,
} from "../../../server/research/StrategyBundleSchema";
import {
  hashCanonical,
  type JsonValue,
} from "../../../server/research/canonical";
import {
  E2E_DATABASE_PATH,
  E2E_RESEARCH_INTEGRITY_HMAC_KEY,
  E2E_RUN_ID,
} from "./environment";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const CAMPAIGN_TITLE = "Repeated and no-progress action reduction";
const DIMENSION_NAME = "loop.max_identical_fingerprints";

export interface ResearchPromotionLifecycleFixture {
  readonly campaignId: string;
  readonly priorExperimentId: string;
  readonly priorStrategyId: string;
  readonly candidateExperimentId: string;
  readonly candidateStrategyId: string;
}

export interface ResearchPromotionActionCandidate {
  readonly action: HumanResearchPromotionAction;
  readonly modality: "pointer" | "keyboard";
  readonly experimentId: string;
  readonly strategyId: string;
}

export interface ResearchPromotionCandidateRef {
  readonly experimentId: string;
  readonly strategyId: string;
}

export interface ResearchPromotionActionMatrixFixture
  extends ResearchPromotionLifecycleFixture {
  readonly actionCandidates: readonly ResearchPromotionActionCandidate[];
}

export interface ResearchPromotionReliabilityFixture
  extends ResearchPromotionLifecycleFixture {
  readonly retryCandidate: ResearchPromotionCandidateRef;
  readonly conflictCandidates: readonly (ResearchPromotionCandidateRef & {
    readonly modality: "pointer" | "keyboard";
  })[];
  readonly skippedStageCandidate: ResearchPromotionCandidateRef;
  readonly invalidCanaryCandidate: ResearchPromotionCandidateRef;
  readonly responseLossAppliedCandidate: ResearchPromotionCandidateRef;
  readonly responseLossUnchangedCandidate: ResearchPromotionCandidateRef;
  readonly differentReviewerCandidate: ResearchPromotionCandidateRef;
}

export interface ResearchPromotionFixtureState {
  readonly state: string;
  readonly version: number;
  readonly transitionActions: readonly string[];
  readonly deployments: readonly {
    readonly deploymentStage: string;
    readonly isolationMode: string;
    readonly maxMissions: number | null;
    readonly maxWallClockMs: number | null;
    readonly status: string;
  }[];
  readonly activations: readonly {
    readonly ordinal: number;
    readonly action: string;
    readonly selectedStrategyVersionId: string;
  }[];
  readonly rollbackCount: number;
  readonly strategyVersionCount: number;
}

interface CandidateFixture {
  readonly experimentId: string;
  readonly strategyId: string;
  readonly exposureReceiptId: string;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) {
    throw new Error("Research promotion E2E requires the isolated V2 database path");
  }
  return E2E_DATABASE_PATH;
}

function stablePrefix(): string {
  const run = E2E_RUN_ID.replace(/[^A-Za-z0-9._-]+/gu, "-").slice(0, 72);
  return `research-promotion-${run}-${randomUUID()}`;
}

function addCandidate(
  database: ReturnType<typeof createDatabaseConnection>,
  repository: ResearchPromotionLifecycleRepository,
  fixture: {
    readonly prefix: string;
    readonly campaignId: string;
    readonly charterId: string;
    readonly dimensionId: string;
    readonly snapshotId: string;
    readonly baselineStrategyId: string;
  },
  name: string,
  version: number,
): CandidateFixture {
  const experimentId = `${fixture.prefix}-experiment-${name}`;
  const strategyId = `${fixture.prefix}-strategy-${name}`;
  const bundle = {
    ...DEFAULT_STRATEGY_BUNDLE,
    loopControl: {
      ...DEFAULT_STRATEGY_BUNDLE.loopControl,
      maxIdenticalFingerprints: name.includes("prior") ? 2 : 4,
    },
  };
  const now = new Date().toISOString();
  database.prepare(`
    INSERT INTO strategy_versions (
      id, campaign_id, parent_id, version, bundle_json, bundle_hash,
      status, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'proposed', 'local-policy', ?)
  `).run(
    strategyId,
    fixture.campaignId,
    fixture.baselineStrategyId,
    version,
    canonicalJson(bundle),
    hashCanonical(bundle),
    now,
  );
  database.prepare(`
    INSERT INTO experiments (
      id, campaign_id, charter_id, dimension_id, baseline_strategy_id,
      candidate_strategy_id, benchmark_snapshot_id, hypothesis, status,
      public_llm_spec_hash, created_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, 'local-policy', ?, ?)
  `).run(
    experimentId,
    fixture.campaignId,
    fixture.charterId,
    fixture.dimensionId,
    fixture.baselineStrategyId,
    strategyId,
    fixture.snapshotId,
    `${name} candidate reduces repeated actions in an isolated fixture.`,
    HASH_C,
    now,
    now,
  );
  const exposure = new LlmExposurePolicy("research-exposure-v1")
    .buildResearchBrief({
      campaignId: fixture.campaignId,
      dimensionId: DIMENSION_NAME,
      objective: "Reduce repeated no-progress actions in isolated fixtures.",
      providerId: "public-proposal-provider",
      modelId: "proposal-model",
      experimentId,
      createdAt: now,
      items: [{
        id: `${fixture.prefix}-sanitized-metric-${name}`,
        kind: "metric_summary",
        classification: "internal",
        disclosureClass: "internal_sanitized",
        content: "Duplicate action rate changed on an anonymous disposable lab fixture.",
        verified: true,
      }],
    }).receipt;
  repository.persistExposureReceipt(exposure);
  repository.initialize({ experimentId, actorId: "local-policy" });
  return {
    experimentId,
    strategyId,
    exposureReceiptId: exposure.id,
  };
}

function createIntegrityReceipt(
  database: ReturnType<typeof createDatabaseConnection>,
  repository: ResearchPromotionLifecycleRepository,
  authority: IntegrityAuthority,
  candidate: CandidateFixture,
  sequence: number,
  evaluationAction: ExperimentIntegrityPayload["evaluationAction"],
) {
  const scope = database.prepare(`
    SELECT
      charter.charter_hash,
      baseline.bundle_hash AS baseline_hash,
      candidate.bundle_hash AS candidate_hash,
      family.evaluator_version,
      snapshot.evaluator_hash,
      snapshot.snapshot_hash,
      snapshot.tool_manifest_hash,
      snapshot.container_image_digest
    FROM experiments experiment
    JOIN research_charters charter ON charter.id = experiment.charter_id
    JOIN strategy_versions baseline ON baseline.id = experiment.baseline_strategy_id
    JOIN strategy_versions candidate ON candidate.id = experiment.candidate_strategy_id
    JOIN benchmark_snapshots snapshot ON snapshot.id = experiment.benchmark_snapshot_id
    JOIN benchmark_families family ON family.id = snapshot.family_id
    WHERE experiment.id = ?
  `).get(candidate.experimentId) as {
    readonly charter_hash: string;
    readonly baseline_hash: string;
    readonly candidate_hash: string;
    readonly evaluator_version: string;
    readonly evaluator_hash: string;
    readonly snapshot_hash: string;
    readonly tool_manifest_hash: string;
    readonly container_image_digest: string;
  } | undefined;
  if (!scope) throw new Error(`Experiment ${candidate.experimentId} has no integrity scope`);
  const payload: ExperimentIntegrityPayload = {
    experimentId: candidate.experimentId,
    charterHash: scope.charter_hash,
    strategyHashes: {
      baseline: scope.baseline_hash,
      candidate: scope.candidate_hash,
    },
    evaluatorVersion: scope.evaluator_version,
    evaluatorHash: scope.evaluator_hash,
    benchmarkSnapshotHash: scope.snapshot_hash,
    containerImageDigest: scope.container_image_digest,
    executionEnvironment: {
      kind: "oci_container",
      identityHash: HASH_A,
    },
    toolManifestHash: scope.tool_manifest_hash,
    providerModel: {
      providerId: "public-proposal-provider",
      modelId: "proposal-model",
      promptTemplateHash: HASH_C,
    },
    contextPackIds: [`context-${candidate.experimentId}`],
    randomSeeds: [`seed-${sequence}`],
    eventHash: sequence % 2 === 0 ? HASH_A : HASH_B,
    evidenceHash: sequence % 2 === 0 ? HASH_B : HASH_C,
    metricsHash: sequence % 2 === 0 ? HASH_C : HASH_A,
    exposureReceiptIds: [candidate.exposureReceiptId],
    evaluationStage: evaluationAction.startsWith("hidden_holdout_")
      ? "hidden_holdout"
      : evaluationAction.split("_", 1)[0] as
        ExperimentIntegrityPayload["evaluationStage"],
    evaluationAction,
    evaluationResult: evaluationAction.endsWith("_pass") ? "pass" : "fail",
    evaluationAttemptId: `attempt-${candidate.experimentId}-${sequence}`,
    hardGateFailures: [],
    signedAt: new Date(Date.now() + sequence * 1_000).toISOString(),
  };
  const receipt = authority.createReceipt(payload);
  repository.persistIntegrityReceipt(receipt);
  return receipt;
}

function localTransition(
  repository: ResearchPromotionLifecycleRepository,
  candidate: CandidateFixture,
  action: LocalResearchPromotionAction,
  integrityReceiptId?: string,
): void {
  const lifecycle = repository.get(candidate.experimentId);
  repository.applyLocalTransition({
    experimentId: candidate.experimentId,
    expectedVersion: lifecycle.version,
    action,
    actorId: action.startsWith("policy_") ? "local-policy" : "local-evaluator",
    rationale: `${action.replaceAll("_", " ")} recorded by the trusted local evaluator.`,
    evidenceRefs: [integrityReceiptId ?? `policy-${action}`],
    ...(integrityReceiptId ? { integrityReceiptId } : {}),
  });
}

function humanTransition(
  repository: ResearchPromotionLifecycleRepository,
  candidate: CandidateFixture,
  action: HumanResearchPromotionAction,
  options: {
    readonly canaryBounds?: {
      readonly maxMissions: number;
      readonly maxWallClockMs: number;
    };
    readonly actorId?: string;
  } = {},
): void {
  const lifecycle = repository.get(candidate.experimentId);
  const { actorId = "e2e-local-operator", ...actionOptions } = options;
  repository.applyHumanTransition({
    experimentId: candidate.experimentId,
    expectedVersion: lifecycle.version,
    action,
    actorId,
    rationale: `${action.replaceAll("_", " ")} approved after signed local evidence review.`,
    evidenceRefs: [lifecycle.latestIntegrityReceiptId ?? `review-${action}`],
    ...actionOptions,
    idempotencyKey: `${candidate.experimentId}-${action}-${lifecycle.version}`,
  });
}

function advanceThroughHoldout(
  database: ReturnType<typeof createDatabaseConnection>,
  repository: ResearchPromotionLifecycleRepository,
  authority: IntegrityAuthority,
  candidate: CandidateFixture,
  sequenceOffset: number,
): void {
  localTransition(repository, candidate, "policy_accept");
  localTransition(repository, candidate, "start_benchmark");
  for (const [offset, action] of [
    "development_pass",
    "validation_pass",
    "hidden_holdout_pass",
  ].entries()) {
    const receipt = createIntegrityReceipt(
      database,
      repository,
      authority,
      candidate,
      sequenceOffset + offset + 1,
      action as ExperimentIntegrityPayload["evaluationAction"],
    );
    localTransition(
      repository,
      candidate,
      action as LocalResearchPromotionAction,
      receipt.id,
    );
  }
}

function verifyPriorCandidate(
  database: ReturnType<typeof createDatabaseConnection>,
  repository: ResearchPromotionLifecycleRepository,
  authority: IntegrityAuthority,
  candidate: CandidateFixture,
): void {
  advanceThroughHoldout(database, repository, authority, candidate, 0);
  humanTransition(repository, candidate, "approve_human_review");
  humanTransition(repository, candidate, "start_shadow");
  const shadow = createIntegrityReceipt(
    database, repository, authority, candidate, 4, "shadow_pass",
  );
  localTransition(repository, candidate, "shadow_pass", shadow.id);
  humanTransition(repository, candidate, "approve_canary");
  humanTransition(repository, candidate, "start_canary", {
    canaryBounds: { maxMissions: 1, maxWallClockMs: 60_000 },
  });
  const canary = createIntegrityReceipt(
    database, repository, authority, candidate, 5, "canary_pass",
  );
  localTransition(repository, candidate, "canary_pass", canary.id);
  humanTransition(repository, candidate, "verify");
}

export function seedResearchPromotionLifecycleFixture():
ResearchPromotionLifecycleFixture {
  const database = createDatabaseConnection({
    filename: databasePath(),
    verifyIntegrity: false,
  });
  try {
    const prefix = stablePrefix();
    const campaignId = `${prefix}-campaign`;
    const dimensionId = `${prefix}-dimension`;
    const charterId = `${prefix}-charter`;
    const benchmarkFamilyId = `${prefix}-benchmark-family`;
    const snapshotId = `${prefix}-snapshot`;
    const developmentScenarioId = `${prefix}-scenario-development`;
    const validationScenarioId = `${prefix}-scenario-validation`;
    const baselineStrategyId = `${prefix}-strategy-baseline`;
    const now = new Date().toISOString();
    database.prepare(`
      INSERT INTO research_campaigns (
        id, name, purpose, status, owner, budgets_json, created_at, updated_at
      ) VALUES (?, ?, ?, 'running', 'e2e-local-operator', ?, ?, ?)
    `).run(
      campaignId,
      CAMPAIGN_TITLE,
      "Browser fixture for the complete human-owned promotion lifecycle.",
      canonicalJson(DEFAULT_RESEARCH_BUDGETS),
      now,
      now,
    );
    database.prepare(`
      INSERT INTO research_dimensions (
        id, campaign_id, name, schema_path
      ) VALUES (?, ?, ?, '/loopControl/maxIdenticalFingerprints')
    `).run(dimensionId, campaignId, DIMENSION_NAME);
    database.prepare(`
      INSERT INTO research_charters (
        id, campaign_id, version, immutable_scope_json,
        mutable_dimensions_json, forbidden_paths_json, budgets_json,
        charter_hash, approved_by, approved_at
      ) VALUES (?, ?, 1, '{}', '[]', '[]', ?, ?, 'e2e-local-operator', ?)
    `).run(
      charterId,
      campaignId,
      canonicalJson(DEFAULT_RESEARCH_BUDGETS),
      HASH_A,
      now,
    );
    database.prepare(`
      INSERT INTO benchmark_families (
        id, name, evaluator_version, hard_gates_json, metrics_json,
        promotion_criteria_json, created_at
      ) VALUES (?, ?, 'security-evaluator-v1', '[]', '[]', '{}', ?)
    `).run(
      benchmarkFamilyId,
      `Promotion fixture ${prefix}`,
      now,
    );
    database.prepare(`
      INSERT INTO benchmark_snapshots (
        id, family_id, evaluator_hash, scenario_set_hash,
        tool_manifest_hash, snapshot_hash, container_image_digest,
        execution_environment_kind, execution_environment_identity_hash,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'oci_container', ?, ?)
    `).run(
      snapshotId,
      benchmarkFamilyId,
      HASH_C,
      HASH_A,
      HASH_B,
      HASH_B,
      `sha256:${HASH_A}`,
      HASH_A,
      now,
    );
    const insertScenario = database.prepare(`
      INSERT INTO benchmark_scenarios (
        id, family_id, split, name, scenario_hash, ground_truth_ref,
        environment_digest, budget_json, active, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, '{}', 1, ?)
    `);
    insertScenario.run(
      developmentScenarioId,
      benchmarkFamilyId,
      "development",
      "Promotion lifecycle development fixture",
      HASH_A,
      "local-fixture://promotion/development",
      `sha256:${HASH_A}`,
      now,
    );
    insertScenario.run(
      validationScenarioId,
      benchmarkFamilyId,
      "validation",
      "Promotion lifecycle validation fixture",
      HASH_B,
      "local-fixture://promotion/validation",
      `sha256:${HASH_B}`,
      now,
    );
    database.prepare(`
      INSERT INTO benchmark_snapshot_scenarios (
        snapshot_id, scenario_id, ordinal
      ) VALUES (?, ?, 1), (?, ?, 2)
    `).run(
      snapshotId,
      developmentScenarioId,
      snapshotId,
      validationScenarioId,
    );
    database.prepare(`
      INSERT INTO strategy_versions (
        id, campaign_id, version, bundle_json, bundle_hash,
        status, created_by, created_at
      ) VALUES (?, ?, 1, ?, ?, 'verified', 'e2e-local-operator', ?)
    `).run(
      baselineStrategyId,
      campaignId,
      canonicalJson(DEFAULT_STRATEGY_BUNDLE),
      hashCanonical(DEFAULT_STRATEGY_BUNDLE as unknown as JsonValue),
      now,
    );
    const authority = new IntegrityAuthority(E2E_RESEARCH_INTEGRITY_HMAC_KEY);
    const repository = new ResearchPromotionLifecycleRepository(
      database,
      authority,
    );
    const shared = {
      prefix,
      campaignId,
      charterId,
      dimensionId,
      snapshotId,
      baselineStrategyId,
    };
    const prior = addCandidate(database, repository, shared, "prior", 2);
    verifyPriorCandidate(database, repository, authority, prior);
    const candidate = addCandidate(
      database,
      repository,
      shared,
      "candidate",
      3,
    );
    advanceThroughHoldout(database, repository, authority, candidate, 10);
    return {
      campaignId,
      priorExperimentId: prior.experimentId,
      priorStrategyId: prior.strategyId,
      candidateExperimentId: candidate.experimentId,
      candidateStrategyId: candidate.strategyId,
    };
  } finally {
    database.close();
  }
}

function campaignFoundation(
  database: ReturnType<typeof createDatabaseConnection>,
  campaignId: string,
) {
  const row = database.prepare(`
    SELECT
      charter.id AS charter_id,
      dimension.id AS dimension_id,
      snapshot.id AS snapshot_id,
      baseline.id AS baseline_strategy_id
    FROM research_campaigns campaign
    JOIN research_charters charter ON charter.campaign_id = campaign.id
    JOIN research_dimensions dimension ON dimension.campaign_id = campaign.id
    JOIN benchmark_snapshots snapshot ON snapshot.id = (
      SELECT experiment.benchmark_snapshot_id
      FROM experiments experiment
      WHERE experiment.campaign_id = campaign.id
      ORDER BY experiment.created_at, experiment.id
      LIMIT 1
    )
    JOIN strategy_versions baseline
      ON baseline.campaign_id = campaign.id AND baseline.version = 1
    WHERE campaign.id = ?
    ORDER BY dimension.id
    LIMIT 1
  `).get(campaignId) as {
    readonly charter_id: string;
    readonly dimension_id: string;
    readonly snapshot_id: string;
    readonly baseline_strategy_id: string;
  } | undefined;
  if (!row) throw new Error(`Research campaign ${campaignId} has no fixture foundation`);
  return {
    prefix: campaignId.replace(/-campaign$/u, ""),
    campaignId,
    charterId: row.charter_id,
    dimensionId: row.dimension_id,
    snapshotId: row.snapshot_id,
    baselineStrategyId: row.baseline_strategy_id,
  };
}

function nextStrategyVersion(
  database: ReturnType<typeof createDatabaseConnection>,
  campaignId: string,
): number {
  const row = database.prepare(`
    SELECT COALESCE(MAX(version), 0) + 1 AS version
    FROM strategy_versions
    WHERE campaign_id = ?
  `).get(campaignId) as { readonly version: number };
  return row.version;
}

function prepareCandidateForHumanAction(
  database: ReturnType<typeof createDatabaseConnection>,
  repository: ResearchPromotionLifecycleRepository,
  authority: IntegrityAuthority,
  candidate: CandidateFixture,
  action: HumanResearchPromotionAction,
  sequenceOffset: number,
): void {
  if (action === "reject") return;
  advanceThroughHoldout(
    database,
    repository,
    authority,
    candidate,
    sequenceOffset,
  );
  if (
    action === "approve_human_review"
    || action === "reject_human_review"
  ) return;
  humanTransition(repository, candidate, "approve_human_review");
  if (action === "start_shadow") return;
  humanTransition(repository, candidate, "start_shadow");
  const shadow = createIntegrityReceipt(
    database,
    repository,
    authority,
    candidate,
      sequenceOffset + 4,
      "shadow_pass",
  );
  localTransition(repository, candidate, "shadow_pass", shadow.id);
  if (action === "approve_canary") return;
  humanTransition(repository, candidate, "approve_canary");
  if (action === "start_canary") return;
  humanTransition(repository, candidate, "start_canary", {
    canaryBounds: { maxMissions: 1, maxWallClockMs: 60_000 },
  });
  const canary = createIntegrityReceipt(
    database,
    repository,
    authority,
    candidate,
      sequenceOffset + 5,
      "canary_pass",
  );
  localTransition(repository, candidate, "canary_pass", canary.id);
  if (action === "verify") return;
  humanTransition(repository, candidate, "verify");
}

export function seedResearchPromotionActionMatrixFixture():
ResearchPromotionActionMatrixFixture {
  const base = seedResearchPromotionLifecycleFixture();
  const database = createDatabaseConnection({
    filename: databasePath(),
    verifyIntegrity: false,
  });
  try {
    const authority = new IntegrityAuthority(E2E_RESEARCH_INTEGRITY_HMAC_KEY);
    const repository = new ResearchPromotionLifecycleRepository(
      database,
      authority,
    );
    const foundation = campaignFoundation(database, base.campaignId);
    const specifications: readonly {
      readonly action: HumanResearchPromotionAction;
      readonly modality: "pointer" | "keyboard";
    }[] = [
      { action: "approve_human_review", modality: "keyboard" },
      { action: "reject_human_review", modality: "pointer" },
      { action: "reject_human_review", modality: "keyboard" },
      { action: "start_shadow", modality: "keyboard" },
      { action: "approve_canary", modality: "keyboard" },
      { action: "start_canary", modality: "keyboard" },
      { action: "verify", modality: "keyboard" },
      { action: "reject", modality: "pointer" },
      { action: "reject", modality: "keyboard" },
      { action: "mark_stale", modality: "pointer" },
      { action: "mark_stale", modality: "keyboard" },
      { action: "supersede", modality: "pointer" },
      { action: "supersede", modality: "keyboard" },
      { action: "rollback", modality: "keyboard" },
    ];
    const actionCandidates = specifications.map((specification, index) => {
      const name = `matrix-${specification.action}-${specification.modality}`;
      const candidate = addCandidate(
        database,
        repository,
        foundation,
        name,
        nextStrategyVersion(database, base.campaignId),
      );
      prepareCandidateForHumanAction(
        database,
        repository,
        authority,
        candidate,
        specification.action,
        100 + index * 10,
      );
      return {
        ...specification,
        experimentId: candidate.experimentId,
        strategyId: candidate.strategyId,
      };
    });
    return { ...base, actionCandidates };
  } finally {
    database.close();
  }
}

export function seedResearchPromotionReliabilityFixture():
ResearchPromotionReliabilityFixture {
  const base = seedResearchPromotionLifecycleFixture();
  const database = createDatabaseConnection({
    filename: databasePath(),
    verifyIntegrity: false,
  });
  try {
    const authority = new IntegrityAuthority(E2E_RESEARCH_INTEGRITY_HMAC_KEY);
    const repository = new ResearchPromotionLifecycleRepository(
      database,
      authority,
    );
    const foundation = campaignFoundation(database, base.campaignId);
    const add = (
      name: string,
      action?: HumanResearchPromotionAction,
      sequenceOffset = 300,
    ): CandidateFixture => {
      const candidate = addCandidate(
        database,
        repository,
        foundation,
        name,
        nextStrategyVersion(database, base.campaignId),
      );
      if (action) {
        prepareCandidateForHumanAction(
          database,
          repository,
          authority,
          candidate,
          action,
          sequenceOffset,
        );
      }
      return candidate;
    };
    const retry = add("reliability-retry", "approve_human_review", 300);
    const conflictPointer = add(
      "reliability-conflict-pointer",
      "approve_human_review",
      320,
    );
    const conflictKeyboard = add(
      "reliability-conflict-keyboard",
      "approve_human_review",
      340,
    );
    const skipped = add("reliability-skipped-stage");
    const invalidCanary = add(
      "reliability-invalid-canary",
      "start_canary",
      360,
    );
    const responseLossApplied = add(
      "reliability-response-loss-applied",
      "approve_human_review",
      380,
    );
    const responseLossUnchanged = add(
      "reliability-response-loss-unchanged",
      "approve_human_review",
      400,
    );
    const differentReviewer = add(
      "reliability-different-reviewer",
      "approve_human_review",
      420,
    );
    return {
      ...base,
      retryCandidate: {
        experimentId: retry.experimentId,
        strategyId: retry.strategyId,
      },
      conflictCandidates: [
        {
          modality: "pointer",
          experimentId: conflictPointer.experimentId,
          strategyId: conflictPointer.strategyId,
        },
        {
          modality: "keyboard",
          experimentId: conflictKeyboard.experimentId,
          strategyId: conflictKeyboard.strategyId,
        },
      ],
      skippedStageCandidate: {
        experimentId: skipped.experimentId,
        strategyId: skipped.strategyId,
      },
      invalidCanaryCandidate: {
        experimentId: invalidCanary.experimentId,
        strategyId: invalidCanary.strategyId,
      },
      responseLossAppliedCandidate: {
        experimentId: responseLossApplied.experimentId,
        strategyId: responseLossApplied.strategyId,
      },
      responseLossUnchangedCandidate: {
        experimentId: responseLossUnchanged.experimentId,
        strategyId: responseLossUnchanged.strategyId,
      },
      differentReviewerCandidate: {
        experimentId: differentReviewer.experimentId,
        strategyId: differentReviewer.strategyId,
      },
    };
  } finally {
    database.close();
  }
}

export function advanceResearchPromotionHumanDecision(
  experimentId: string,
  action: HumanResearchPromotionAction,
  actorId = "e2e-local-operator",
): void {
  const database = createDatabaseConnection({
    filename: databasePath(),
    verifyIntegrity: false,
  });
  try {
    const repository = new ResearchPromotionLifecycleRepository(
      database,
      new IntegrityAuthority(E2E_RESEARCH_INTEGRITY_HMAC_KEY),
    );
    const row = database.prepare(`
      SELECT candidate_strategy_id
      FROM experiments
      WHERE id = ?
    `).get(experimentId) as {
      readonly candidate_strategy_id: string;
    } | undefined;
    if (!row) throw new Error(`Experiment ${experimentId} does not exist`);
    const exposure = database.prepare(`
      SELECT id
      FROM provider_exposure_receipts
      WHERE experiment_id = ?
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `).get(experimentId) as { readonly id: string } | undefined;
    if (!exposure) throw new Error(`Experiment ${experimentId} has no exposure receipt`);
    humanTransition(repository, {
      experimentId,
      strategyId: row.candidate_strategy_id,
      exposureReceiptId: exposure.id,
    }, action, { actorId });
  } finally {
    database.close();
  }
}

export function readResearchPromotionCandidateVersion(
  experimentId: string,
): { readonly state: string; readonly version: number } {
  const database = createDatabaseConnection({
    filename: databasePath(),
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const row = database.prepare(`
      SELECT version, json_extract(promotion_record_json, '$.state') AS state
      FROM research_promotion_lifecycles
      WHERE experiment_id = ?
    `).get(experimentId) as {
      readonly state: string;
      readonly version: number;
    } | undefined;
    if (!row) throw new Error(`Promotion lifecycle ${experimentId} is missing`);
    return row;
  } finally {
    database.close();
  }
}

export function recordResearchPromotionEvaluatorPass(
  fixture: ResearchPromotionLifecycleFixture,
  action: "shadow_pass" | "canary_pass",
): void {
  const database = createDatabaseConnection({
    filename: databasePath(),
    verifyIntegrity: false,
  });
  try {
    const authority = new IntegrityAuthority(E2E_RESEARCH_INTEGRITY_HMAC_KEY);
    const repository = new ResearchPromotionLifecycleRepository(
      database,
      authority,
    );
    const exposure = database.prepare(`
      SELECT id
      FROM provider_exposure_receipts
      WHERE experiment_id = ?
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `).get(fixture.candidateExperimentId) as {
      readonly id: string;
    } | undefined;
    if (!exposure) throw new Error("Candidate exposure receipt is missing");
    const candidate = {
      experimentId: fixture.candidateExperimentId,
      strategyId: fixture.candidateStrategyId,
      exposureReceiptId: exposure.id,
    };
    const receipt = createIntegrityReceipt(
      database,
      repository,
      authority,
      candidate,
      action === "shadow_pass" ? 20 : 21,
      action,
    );
    localTransition(repository, candidate, action, receipt.id);
  } finally {
    database.close();
  }
}

export function readResearchPromotionFixtureState(
  fixture: ResearchPromotionLifecycleFixture,
): ResearchPromotionFixtureState {
  const database = createDatabaseConnection({
    filename: databasePath(),
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const lifecycle = database.prepare(`
      SELECT version, json_extract(promotion_record_json, '$.state') AS state
      FROM research_promotion_lifecycles
      WHERE experiment_id = ?
    `).get(fixture.candidateExperimentId) as {
      readonly version: number;
      readonly state: string;
    } | undefined;
    if (!lifecycle) throw new Error("Candidate lifecycle is missing");
    const transitions = database.prepare(`
      SELECT action
      FROM research_promotion_transitions
      WHERE experiment_id = ?
      ORDER BY sequence
    `).all(fixture.candidateExperimentId) as Array<{
      readonly action: string;
    }>;
    const deployments = database.prepare(`
      SELECT deployment_stage, isolation_mode, max_missions,
        max_wall_clock_ms, status
      FROM strategy_deployments
      WHERE strategy_version_id = ?
      ORDER BY lifecycle_version, id
    `).all(fixture.candidateStrategyId) as Array<{
      readonly deployment_stage: string;
      readonly isolation_mode: string;
      readonly max_missions: number | null;
      readonly max_wall_clock_ms: number | null;
      readonly status: string;
    }>;
    const activations = database.prepare(`
      SELECT ordinal, action, selected_strategy_version_id
      FROM research_strategy_activation_versions
      WHERE campaign_id = ?
      ORDER BY ordinal
    `).all(fixture.campaignId) as Array<{
      readonly ordinal: number;
      readonly action: string;
      readonly selected_strategy_version_id: string;
    }>;
    const rollback = database.prepare(`
      SELECT COUNT(*) AS count
      FROM strategy_rollbacks
      WHERE from_strategy_id = ?
    `).get(fixture.candidateStrategyId) as { readonly count: number };
    const strategies = database.prepare(`
      SELECT COUNT(*) AS count
      FROM strategy_versions
      WHERE campaign_id = ?
    `).get(fixture.campaignId) as { readonly count: number };
    return {
      state: lifecycle.state,
      version: lifecycle.version,
      transitionActions: transitions.map(({ action }) => action),
      deployments: deployments.map((deployment) => ({
        deploymentStage: deployment.deployment_stage,
        isolationMode: deployment.isolation_mode,
        maxMissions: deployment.max_missions,
        maxWallClockMs: deployment.max_wall_clock_ms,
        status: deployment.status,
      })),
      activations: activations.map((activation) => ({
        ordinal: activation.ordinal,
        action: activation.action,
        selectedStrategyVersionId: activation.selected_strategy_version_id,
      })),
      rollbackCount: rollback.count,
      strategyVersionCount: strategies.count,
    };
  } finally {
    database.close();
  }
}

export function completeResearchPromotionLifecycleFixture(
  fixture: ResearchPromotionLifecycleFixture,
): void {
  const database = createDatabaseConnection({
    filename: databasePath(),
    verifyIntegrity: false,
  });
  try {
    database.prepare(`
      UPDATE research_campaigns
      SET status = 'completed', updated_at = ?
      WHERE id = ?
    `).run(new Date().toISOString(), fixture.campaignId);
  } finally {
    database.close();
  }
}

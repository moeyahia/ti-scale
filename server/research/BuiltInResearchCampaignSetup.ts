import {
  DEFAULT_STRATEGY_BUNDLE,
  FORBIDDEN_STRATEGY_PATH_PREFIXES,
  applyStrategyPatch,
  type MutableStrategyPath,
  type StrategyBundle,
  type StrategyPatchOperation,
} from "./StrategyBundleSchema";
import { isolatedExperimentWorkerSourceSha256 } from "./IsolatedExperimentWorkerLauncher";
import { BUILT_IN_SYNTHETIC_BENCHMARK_FIXTURES } from "./SyntheticResearchFixtures";
import {
  HARD_GATE_CODES,
  SecurityEvaluationHarness,
  type BenchmarkSplit,
  type TrustedBenchmarkScenario,
} from "./SecurityEvaluationHarness";
import {
  INITIAL_RESEARCH_DIMENSIONS,
  campaignDefinition,
  type InitialResearchCampaignId,
  type InitialResearchDimensionId,
} from "./ResearchTypes";
import type {
  PrivateResearchHoldoutBinding,
  PrivateResearchHoldoutRegistry,
} from "./PrivateResearchHoldout";
import {
  canonicalJson,
  deepFreeze,
  hashCanonical,
  type JsonValue,
} from "./canonical";

export interface BuiltInResearchCampaignSetup {
  readonly schemaVersion: "ti-scale.built-in-research-setup.v1";
  readonly catalogId: InitialResearchCampaignId;
  readonly candidatePresetId: string;
  readonly dimensionId: InitialResearchDimensionId;
  readonly path: MutableStrategyPath;
  readonly hypothesis: string;
  readonly patch: readonly [StrategyPatchOperation];
  readonly baselineBundle: StrategyBundle;
  readonly baselineBundleHash: string;
  readonly candidateBundle: StrategyBundle;
  readonly candidateBundleHash: string;
  readonly patchHash: string;
  readonly family: {
    readonly id: string;
    readonly name: string;
    readonly evaluatorVersion: string;
    readonly hardGatesJson: string;
    readonly metricsJson: string;
    readonly promotionCriteriaJson: string;
  };
  /**
   * Public development and validation fixtures may be reviewed in source.
   * When a trusted operator descriptor is configured, the third record is an
   * opaque commitment-bound hidden holdout. Its private identity and ground
   * truth remain inside PrivateResearchHoldoutRegistry.
   */
  readonly scenarios: readonly {
    readonly id: string;
    readonly split: BenchmarkSplit;
    readonly name: string;
    readonly scenarioHash: string;
    readonly groundTruthRef: string;
    readonly environmentDigest: string;
    readonly budgetJson: string;
  }[];
  /** Safe hashes only; never contains fixtureKey, input, or ground truth. */
  readonly privateHoldoutBinding?: PrivateResearchHoldoutBinding;
  readonly snapshot: {
    readonly id: string;
    readonly evaluatorHash: string;
    readonly scenarioSetHash: string;
    readonly toolManifestHash: string;
    readonly snapshotHash: string;
  };
  readonly executionEnvironment: BuiltInResearchExecutionEnvironment;
  readonly executionBoundary: {
    readonly targetClass: "synthetic_fixture";
    readonly liveClientTargetAllowed: false;
    readonly outboundNetworkAllowed: false;
    readonly publicProviderUsed: false;
    readonly arbitrarySourcePatchAllowed: false;
    readonly automaticPromotionAllowed: false;
    readonly automaticDeploymentAllowed: false;
  };
}

interface SetupSeed {
  readonly catalogId: InitialResearchCampaignId;
  readonly dimensionId: InitialResearchDimensionId;
  readonly path: MutableStrategyPath;
  readonly candidateValue: number;
  readonly fixtureId: string;
  readonly validationFixtureId: string;
  readonly label: string;
  readonly hypothesis: string;
  readonly primaryMetric: string;
  readonly primaryMetricDirection: "higher_better" | "lower_better";
}

const SETUP_SEEDS: readonly SetupSeed[] = Object.freeze([
  {
    catalogId: "repeated_no_progress_action_reduction",
    dimensionId: "loop.max_identical_fingerprints",
    path: "/loopControl/maxIdenticalFingerprints",
    candidateValue: 2,
    fixtureId: "synthetic-repeated-no-progress-v1",
    validationFixtureId: "synthetic-validation-repeated-no-progress-v1",
    label: "Repeated-action guard",
    hypothesis:
      "Reducing the identical-action bound from three to two will prevent repeated no-progress work while preserving the synthetic fixture integrity gate.",
    primaryMetric: "duplicate_action_rate",
    primaryMetricDirection: "lower_better",
  },
  {
    catalogId: "specialist_routing_quality",
    dimensionId: "routing.minimum_capability_score",
    path: "/specialistRouting/minimumCapabilityScore",
    candidateValue: 0.78,
    fixtureId: "synthetic-specialist-routing-v1",
    validationFixtureId: "synthetic-validation-specialist-routing-v1",
    label: "Specialist capability threshold",
    hypothesis:
      "Raising the specialist capability threshold from 0.70 to 0.78 will improve bounded routing selectivity without enabling commander execution.",
    primaryMetric: "specialist_routing_quality",
    primaryMetricDirection: "higher_better",
  },
  {
    catalogId: "memory_retrieval_precision",
    dimensionId: "memory.minimum_confidence",
    path: "/memoryRetrieval/minimumConfidence",
    candidateValue: 0.72,
    fixtureId: "synthetic-memory-retrieval-v1",
    validationFixtureId: "synthetic-validation-memory-retrieval-v1",
    label: "Memory confidence threshold",
    hypothesis:
      "Raising the memory confidence threshold from 0.65 to 0.72 will reduce irrelevant retrieval while preserving engagement isolation.",
    primaryMetric: "memory_retrieval_precision",
    primaryMetricDirection: "higher_better",
  },
]);

const EVALUATOR_VERSION = "ti-scale-local-synthetic-evaluator-v1";
const WORKER_SOURCE_HASH = isolatedExperimentWorkerSourceSha256();
const PROMOTION_CRITERIA = Object.freeze({
  result: "development_result_only",
  automaticPromotion: false,
  automaticDeployment: false,
  humanReviewRequired: true,
  privateHoldoutDescriptorRequired: true,
  additionalSplitsRequiredBeforePromotion: [
    "validation",
    "hidden_holdout",
    "shadow",
    "bounded_canary",
  ],
});
const EXECUTION_BOUNDARY = Object.freeze({
  targetClass: "synthetic_fixture" as const,
  liveClientTargetAllowed: false as const,
  outboundNetworkAllowed: false as const,
  publicProviderUsed: false as const,
  arbitrarySourcePatchAllowed: false as const,
  automaticPromotionAllowed: false as const,
  automaticDeploymentAllowed: false as const,
});

export interface BuiltInResearchExecutionEnvironment {
  readonly kind: "local_bwrap";
  readonly identityHash: string;
  readonly toolManifestHash: string;
  readonly workerSourceHash: string;
}

export interface BuiltInResearchCampaignSeedPreview {
  readonly candidatePresetId: string;
  readonly catalogId: InitialResearchCampaignId;
  readonly dimensionId: InitialResearchDimensionId;
  readonly path: MutableStrategyPath;
  readonly hypothesis: string;
  readonly patch: readonly [{
    readonly op: "replace";
    readonly path: MutableStrategyPath;
    readonly value: number;
  }];
  readonly developmentScenarioId: string;
  readonly validationScenarioId: string;
  readonly privateHoldout: "operator_descriptor_required";
}

function requireHash(value: string, label: string): void {
  if (!/^[a-f0-9]{64}$/u.test(value)) {
    throw new Error(`${label} must be a current trusted SHA-256 hash.`);
  }
}

function build(
  seed: SetupSeed,
  executionEnvironment: BuiltInResearchExecutionEnvironment,
  privateHoldout?: PrivateResearchHoldoutRegistry,
): BuiltInResearchCampaignSetup {
  requireHash(
    executionEnvironment.identityHash,
    "Research execution-environment identity",
  );
  requireHash(
    executionEnvironment.toolManifestHash,
    "Research tool manifest",
  );
  requireHash(
    executionEnvironment.workerSourceHash,
    "Research evaluator source",
  );
  if (executionEnvironment.workerSourceHash !== WORKER_SOURCE_HASH) {
    throw new Error(
      "Research runtime evaluator source differs from the reviewed isolated worker source.",
    );
  }
  const registeredDimension = INITIAL_RESEARCH_DIMENSIONS.find(
    ({ id, campaignId, path }) =>
      id === seed.dimensionId
      && campaignId === seed.catalogId
      && path === seed.path,
  );
  if (!registeredDimension) {
    throw new Error(
      `Built-in Research setup ${seed.catalogId} is not bound to its registered strategy dimension.`,
    );
  }
  const fixtureIds = [
    seed.fixtureId,
    seed.validationFixtureId,
  ] as const;
  const fixtures = fixtureIds.map((fixtureId) =>
    BUILT_IN_SYNTHETIC_BENCHMARK_FIXTURES.find(
      ({ scenarioId }) => scenarioId === fixtureId,
    ));
  if (fixtures.some((fixture) => !fixture)) {
    throw new Error(
      `Built-in Research setup ${seed.catalogId} is missing one of its reviewed synthetic fixtures.`,
    );
  }
  const patch = Object.freeze([{
    op: "replace" as const,
    path: seed.path,
    value: seed.candidateValue,
  }]) as readonly [StrategyPatchOperation];
  const applied = applyStrategyPatch(
    DEFAULT_STRATEGY_BUNDLE,
    patch,
    {
      approvedMutablePaths: [seed.path],
      forbiddenPathPrefixes: FORBIDDEN_STRATEGY_PATH_PREFIXES,
      maxOperations: 1,
    },
  );
  const familyId = `builtin-research-family-${seed.catalogId}-v1`;
  const scenarioBudget = {
    wallClockMs: 30_000,
    publicLlmTokens: 0,
    estimatedCost: 0,
    toolCalls: 0,
    outboundNetwork: "disabled",
    liveTargets: 0,
  };
  const splits = [
    "development",
    "validation",
  ] as const satisfies readonly BenchmarkSplit[];
  const publicScenarios = fixtures.map((possibleFixture, index) => {
    const fixture = possibleFixture!;
    const split = splits[index]!;
    const groundTruthRef =
      `builtin://ti-scale/research/${seed.catalogId}/ground-truth/${split}/v1`;
    const scenarioHash = hashCanonical({
      id: fixture.scenarioId,
      familyId,
      split,
      groundTruthRef,
      environmentDigest: fixture.environmentDigest,
      budget: scenarioBudget,
    } as unknown as JsonValue);
    return {
      id: fixture.scenarioId,
      split,
      name: `${seed.label} ${split.replace("_", " ")} fixture`,
      scenarioHash,
      groundTruthRef,
      environmentDigest: fixture.environmentDigest,
      budgetJson: canonicalJson(scenarioBudget as unknown as JsonValue),
    };
  });
  const privateScenario = privateHoldout?.scenarioFor({
    catalogId: seed.catalogId,
    familyId,
    budgetJson: canonicalJson(scenarioBudget as unknown as JsonValue),
  });
  const scenarios: BuiltInResearchCampaignSetup["scenarios"] = [
    ...publicScenarios,
    ...(privateScenario
      ? [{
          id: privateScenario.id,
          split: privateScenario.split,
          name: privateScenario.name,
          scenarioHash: privateScenario.scenarioHash,
          groundTruthRef: privateScenario.groundTruthRef,
          environmentDigest: privateScenario.environmentDigest,
          budgetJson: privateScenario.budgetJson,
        }]
      : []),
  ];
  const trustedScenarios: readonly TrustedBenchmarkScenario[] =
    scenarios.map((scenario) => ({
      id: scenario.id,
      familyId,
      split: scenario.split,
      name: scenario.name,
      scenarioHash: scenario.scenarioHash,
      groundTruthRef: scenario.groundTruthRef,
      environmentDigest: scenario.environmentDigest,
    }));
  const scenarioSetHash = hashCanonical((
    trustedScenarios
      .map(({ id, split, scenarioHash, environmentDigest }) => ({
        id,
        split,
        scenarioHash,
        environmentDigest,
      }))
      .sort((left, right) => left.id.localeCompare(right.id))
  ) as unknown as JsonValue);
  const snapshotHash = hashCanonical({
    familyId,
    evaluatorVersion: EVALUATOR_VERSION,
    scenarioSetHash,
    toolManifestHash: executionEnvironment.toolManifestHash,
    executionEnvironment,
  } as unknown as JsonValue);
  const evaluator = new SecurityEvaluationHarness({
    evaluatorVersion: EVALUATOR_VERSION,
    benchmarkSnapshotHash: snapshotHash,
    metricDirections: {
      fixture_integrity: "gate",
      [seed.primaryMetric]: seed.primaryMetricDirection,
    },
    metricThresholdGates: [],
    nonRegressionTolerance: {
      fixture_integrity: 0,
    },
  }, trustedScenarios);
  return deepFreeze({
    schemaVersion: "ti-scale.built-in-research-setup.v1",
    catalogId: seed.catalogId,
    candidatePresetId: `builtin-candidate-${seed.catalogId}-v1`,
    dimensionId: seed.dimensionId,
    path: seed.path,
    hypothesis: seed.hypothesis,
    patch,
    baselineBundle: DEFAULT_STRATEGY_BUNDLE,
    baselineBundleHash: hashCanonical(
      DEFAULT_STRATEGY_BUNDLE as unknown as JsonValue,
    ),
    candidateBundle: applied.bundle,
    candidateBundleHash: applied.bundleHash,
    patchHash: applied.patchHash,
    family: {
      id: familyId,
      name: `Built-in ${seed.label} synthetic benchmark v1`,
      evaluatorVersion: EVALUATOR_VERSION,
      hardGatesJson: canonicalJson(HARD_GATE_CODES as unknown as JsonValue),
      metricsJson: canonicalJson([
        {
          name: "fixture_integrity",
          direction: "gate",
          authoritativeSource: "local_evaluator",
        },
        {
          name: seed.primaryMetric,
          direction: seed.primaryMetricDirection,
          authoritativeSource: "local_evaluator",
        },
      ] as unknown as JsonValue),
      promotionCriteriaJson: canonicalJson(
        PROMOTION_CRITERIA as unknown as JsonValue,
      ),
    },
    scenarios,
    ...(privateScenario
      ? { privateHoldoutBinding: privateScenario.binding }
      : {}),
    snapshot: {
      id: privateScenario
        ? `builtin-research-snapshot-${seed.catalogId}-v1-${scenarioSetHash.slice(0, 16)}`
        : `builtin-research-snapshot-${seed.catalogId}-v1`,
      evaluatorHash: evaluator.evaluatorHash,
      scenarioSetHash,
      toolManifestHash: executionEnvironment.toolManifestHash,
      snapshotHash,
    },
    executionEnvironment,
    executionBoundary: EXECUTION_BOUNDARY,
  });
}

export function builtInResearchCampaignSetup(
  catalogId: InitialResearchCampaignId,
  executionEnvironment: BuiltInResearchExecutionEnvironment,
  privateHoldout?: PrivateResearchHoldoutRegistry,
): BuiltInResearchCampaignSetup {
  const seed = SETUP_SEEDS.find(
    (candidate) => candidate.catalogId === catalogId,
  );
  if (!seed) {
    throw new Error(
      `No reviewed built-in Research setup exists for ${catalogId}.`,
    );
  }
  return build(seed, executionEnvironment, privateHoldout);
}

export function builtInResearchCampaignSeedPreview(
  catalogId: InitialResearchCampaignId,
): BuiltInResearchCampaignSeedPreview {
  const seed = SETUP_SEEDS.find(
    (candidate) => candidate.catalogId === catalogId,
  );
  if (!seed) {
    throw new Error(
      `No reviewed built-in Research setup exists for ${catalogId}.`,
    );
  }
  return deepFreeze({
    candidatePresetId: `builtin-candidate-${seed.catalogId}-v1`,
    catalogId: seed.catalogId,
    dimensionId: seed.dimensionId,
    path: seed.path,
    hypothesis: seed.hypothesis,
    patch: [{
      op: "replace",
      path: seed.path,
      value: seed.candidateValue,
    }],
    developmentScenarioId: seed.fixtureId,
    validationScenarioId: seed.validationFixtureId,
    privateHoldout: "operator_descriptor_required",
  });
}

export function createBuiltInResearchEvaluationHarness(
  setup: BuiltInResearchCampaignSetup,
): SecurityEvaluationHarness {
  const scenarios: readonly TrustedBenchmarkScenario[] =
    setup.scenarios.map((scenario) => ({
      id: scenario.id,
      familyId: setup.family.id,
      split: scenario.split,
      name: scenario.name,
      scenarioHash: scenario.scenarioHash,
      groundTruthRef: scenario.groundTruthRef,
      environmentDigest: scenario.environmentDigest,
    }));
  const harness = new SecurityEvaluationHarness({
    evaluatorVersion: setup.family.evaluatorVersion,
    benchmarkSnapshotHash: setup.snapshot.snapshotHash,
    metricDirections: {
      fixture_integrity: "gate",
      [campaignDefinition(setup.catalogId).primaryMetric]:
        campaignDefinition(setup.catalogId).primaryMetricDirection,
    },
    metricThresholdGates: [],
    nonRegressionTolerance: {
      fixture_integrity: 0,
    },
  }, scenarios);
  if (harness.evaluatorHash !== setup.snapshot.evaluatorHash) {
    throw new Error(
      `Built-in Research evaluator ${setup.catalogId} does not match its immutable snapshot binding.`,
    );
  }
  return harness;
}

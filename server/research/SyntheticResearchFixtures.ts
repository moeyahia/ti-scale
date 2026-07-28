import {
  syntheticFixtureEnvironmentDigest,
  type SyntheticBenchmarkFixture,
} from "./LabEnvironmentManager";
import type { StrategyBundle } from "./StrategyBundleSchema";
import {
  canonicalJson,
  deepFreeze,
  hashCanonical,
  type JsonValue,
} from "./canonical";

export type SyntheticResearchTrack =
  | "repeated_no_progress_action_reduction"
  | "specialist_routing_quality"
  | "memory_retrieval_precision";

export interface LoopAction {
  readonly fingerprint: string;
  readonly progress: boolean;
}

export interface RoutingCandidate {
  readonly agentId: string;
  readonly capabilities: readonly string[];
  readonly capabilityScore: number;
}

export interface RoutingTask {
  readonly taskId: string;
  readonly requiredCapability: string;
  readonly candidates: readonly RoutingCandidate[];
}

export interface MemoryCandidate {
  readonly memoryId: string;
  readonly confidence: number;
  readonly verified: boolean;
  readonly sameEngagement: boolean;
}

export type SyntheticScenarioInput =
  | {
      readonly schemaVersion: "ti-scale.synthetic-scenario.v1";
      readonly track: "repeated_no_progress_action_reduction";
      readonly actions: readonly LoopAction[];
    }
  | {
      readonly schemaVersion: "ti-scale.synthetic-scenario.v1";
      readonly track: "specialist_routing_quality";
      readonly tasks: readonly RoutingTask[];
    }
  | {
      readonly schemaVersion: "ti-scale.synthetic-scenario.v1";
      readonly track: "memory_retrieval_precision";
      readonly candidates: readonly MemoryCandidate[];
    };

export type SyntheticResearchDecision =
  | {
      readonly kind: "loop_control";
      readonly executedActionIndexes: readonly number[];
      readonly preventedActionIndexes: readonly number[];
    }
  | {
      readonly kind: "specialist_routing";
      readonly assignments: readonly {
        readonly taskId: string;
        readonly agentId: string | null;
      }[];
    }
  | {
      readonly kind: "memory_retrieval";
      readonly selectedMemoryIds: readonly string[];
    };

export interface SyntheticScenarioDefinition {
  readonly scenarioId: string;
  readonly track: SyntheticResearchTrack;
  readonly split: "development" | "validation" | "hidden_holdout";
  readonly input: SyntheticScenarioInput;
  /**
   * Trusted evaluator-only expected labels. They are never materialized in the
   * disposable worker fixture.
   */
  readonly groundTruth: JsonValue;
}

const SCENARIOS: readonly SyntheticScenarioDefinition[] = deepFreeze([
  {
    scenarioId: "synthetic-repeated-no-progress-v1",
    track: "repeated_no_progress_action_reduction",
    split: "development",
    input: {
      schemaVersion: "ti-scale.synthetic-scenario.v1",
      track: "repeated_no_progress_action_reduction",
      actions: [
        { fingerprint: "recon:https", progress: false },
        { fingerprint: "recon:https", progress: false },
        { fingerprint: "recon:https", progress: false },
        { fingerprint: "recon:https", progress: false },
        { fingerprint: "parse:service", progress: true },
        { fingerprint: "recon:smb", progress: false },
        { fingerprint: "recon:smb", progress: false },
        { fingerprint: "recon:smb", progress: false },
      ],
    },
    groundTruth: {
      usefulActionIndexes: [0, 1, 4, 5, 6],
    },
  },
  {
    scenarioId: "synthetic-validation-repeated-no-progress-v1",
    track: "repeated_no_progress_action_reduction",
    split: "validation",
    input: {
      schemaVersion: "ti-scale.synthetic-scenario.v1",
      track: "repeated_no_progress_action_reduction",
      actions: [
        { fingerprint: "dns:enumerate", progress: false },
        { fingerprint: "dns:enumerate", progress: false },
        { fingerprint: "dns:enumerate", progress: false },
        { fingerprint: "http:capture", progress: true },
        { fingerprint: "http:fuzz", progress: false },
        { fingerprint: "http:fuzz", progress: false },
        { fingerprint: "http:fuzz", progress: false },
      ],
    },
    groundTruth: {
      usefulActionIndexes: [0, 1, 3, 4, 5],
    },
  },
  {
    scenarioId: "synthetic-specialist-routing-v1",
    track: "specialist_routing_quality",
    split: "development",
    input: {
      schemaVersion: "ti-scale.synthetic-scenario.v1",
      track: "specialist_routing_quality",
      tasks: [
        {
          taskId: "web-fingerprint",
          requiredCapability: "web",
          candidates: [
            { agentId: "generalist", capabilities: ["web"], capabilityScore: 0.73 },
            { agentId: "web-specialist", capabilities: ["web", "http"], capabilityScore: 0.92 },
          ],
        },
        {
          taskId: "directory-services",
          requiredCapability: "active_directory",
          candidates: [
            { agentId: "network-specialist", capabilities: ["network"], capabilityScore: 0.89 },
            { agentId: "identity-specialist", capabilities: ["active_directory"], capabilityScore: 0.87 },
          ],
        },
        {
          taskId: "high-risk-cloud-change",
          requiredCapability: "cloud",
          candidates: [
            { agentId: "generalist", capabilities: ["cloud"], capabilityScore: 0.74 },
          ],
        },
      ],
    },
    groundTruth: {
      assignments: {
        "web-fingerprint": "web-specialist",
        "directory-services": "identity-specialist",
        "high-risk-cloud-change": null,
      },
    },
  },
  {
    scenarioId: "synthetic-validation-specialist-routing-v1",
    track: "specialist_routing_quality",
    split: "validation",
    input: {
      schemaVersion: "ti-scale.synthetic-scenario.v1",
      track: "specialist_routing_quality",
      tasks: [
        {
          taskId: "binary-triage",
          requiredCapability: "reverse_engineering",
          candidates: [
            { agentId: "re-specialist", capabilities: ["reverse_engineering"], capabilityScore: 0.91 },
            { agentId: "web-specialist", capabilities: ["web"], capabilityScore: 0.95 },
          ],
        },
        {
          taskId: "cloud-inventory",
          requiredCapability: "cloud",
          candidates: [
            { agentId: "cloud-specialist", capabilities: ["cloud"], capabilityScore: 0.83 },
            { agentId: "generalist", capabilities: ["cloud"], capabilityScore: 0.71 },
          ],
        },
      ],
    },
    groundTruth: {
      assignments: {
        "binary-triage": "re-specialist",
        "cloud-inventory": "cloud-specialist",
      },
    },
  },
  {
    scenarioId: "synthetic-memory-retrieval-v1",
    track: "memory_retrieval_precision",
    split: "development",
    input: {
      schemaVersion: "ti-scale.synthetic-scenario.v1",
      track: "memory_retrieval_precision",
      candidates: [
        { memoryId: "memory-current-technique", confidence: 0.94, verified: true, sameEngagement: true },
        { memoryId: "memory-stale-low-confidence", confidence: 0.66, verified: true, sameEngagement: true },
        { memoryId: "memory-cross-engagement", confidence: 0.98, verified: true, sameEngagement: false },
        { memoryId: "memory-unverified", confidence: 0.91, verified: false, sameEngagement: true },
      ],
    },
    groundTruth: {
      relevantMemoryIds: ["memory-current-technique"],
    },
  },
  {
    scenarioId: "synthetic-validation-memory-retrieval-v1",
    track: "memory_retrieval_precision",
    split: "validation",
    input: {
      schemaVersion: "ti-scale.synthetic-scenario.v1",
      track: "memory_retrieval_precision",
      candidates: [
        { memoryId: "memory-recovery-match", confidence: 0.88, verified: true, sameEngagement: true },
        { memoryId: "memory-weak-match", confidence: 0.69, verified: true, sameEngagement: true },
        { memoryId: "memory-other-customer", confidence: 0.99, verified: true, sameEngagement: false },
      ],
    },
    groundTruth: {
      relevantMemoryIds: ["memory-recovery-match"],
    },
  },
] as unknown as JsonValue) as unknown as readonly SyntheticScenarioDefinition[];

function fixture(definition: SyntheticScenarioDefinition): SyntheticBenchmarkFixture {
  const files = Object.freeze({
    "scenario.json": canonicalJson(definition.input as unknown as JsonValue),
  });
  return Object.freeze({
    scenarioId: definition.scenarioId,
    targetClass: "synthetic_fixture",
    files,
    environmentDigest: syntheticFixtureEnvironmentDigest(files),
  });
}

export const BUILT_IN_SYNTHETIC_BENCHMARK_FIXTURES:
readonly SyntheticBenchmarkFixture[] = Object.freeze(SCENARIOS.map(fixture));

export function syntheticScenarioDefinition(
  scenarioId: string,
): SyntheticScenarioDefinition | undefined {
  return SCENARIOS.find((scenario) => scenario.scenarioId === scenarioId);
}

export function syntheticResearchDecision(
  scenarioId: string,
  candidate: StrategyBundle,
): SyntheticResearchDecision {
  const definition = syntheticScenarioDefinition(scenarioId);
  if (!definition) throw new Error(`Unknown public synthetic scenario ${scenarioId}.`);
  return syntheticResearchDecisionForDefinition(definition, candidate);
}

export function syntheticResearchDecisionForDefinition(
  definition: SyntheticScenarioDefinition,
  candidate: StrategyBundle,
): SyntheticResearchDecision {
  const input = definition.input;
  if (input.track === "repeated_no_progress_action_reduction") {
    const executed: number[] = [];
    const prevented: number[] = [];
    let previous = "";
    let repeatedNoProgress = 0;
    input.actions.forEach((action, index) => {
      if (action.progress) {
        previous = "";
        repeatedNoProgress = 0;
        executed.push(index);
        return;
      }
      repeatedNoProgress = action.fingerprint === previous
        ? repeatedNoProgress + 1
        : 1;
      previous = action.fingerprint;
      if (
        repeatedNoProgress
        > candidate.loopControl.maxIdenticalFingerprints
      ) prevented.push(index);
      else executed.push(index);
    });
    return deepFreeze({
      kind: "loop_control",
      executedActionIndexes: executed,
      preventedActionIndexes: prevented,
    });
  }
  if (input.track === "specialist_routing_quality") {
    return deepFreeze({
      kind: "specialist_routing",
      assignments: input.tasks.map((task) => {
        const eligible = task.candidates
          .filter((item) =>
            item.capabilities.includes(task.requiredCapability)
            && item.capabilityScore
              >= candidate.specialistRouting.minimumCapabilityScore)
          .sort((left, right) =>
            right.capabilityScore - left.capabilityScore
            || left.agentId.localeCompare(right.agentId));
        return {
          taskId: task.taskId,
          agentId: eligible[0]?.agentId ?? null,
        };
      }),
    });
  }
  return deepFreeze({
    kind: "memory_retrieval",
    selectedMemoryIds: input.candidates
      .filter((item) =>
        item.verified
        && item.sameEngagement
        && item.confidence >= candidate.memoryRetrieval.minimumConfidence)
      .map(({ memoryId }) => memoryId)
      .sort(),
  });
}

export interface LocalSyntheticScenarioEvaluation {
  readonly metrics: Readonly<Record<string, number>>;
  readonly gateSignals: readonly ("integrity_receipt_mismatch" | "cross_engagement_memory_leak")[];
  readonly eventHash: string;
  readonly evidenceHash: string;
}

export function evaluateSyntheticResearchDecision(input: {
  readonly scenarioId: string;
  readonly candidate: StrategyBundle;
  readonly workerDecision: SyntheticResearchDecision;
  readonly fixtureIntegrity: boolean;
  readonly fixtureHash: string;
  readonly admissionHash: string;
}): LocalSyntheticScenarioEvaluation {
  const definition = syntheticScenarioDefinition(input.scenarioId);
  if (!definition) throw new Error(`Unknown public synthetic scenario ${input.scenarioId}.`);
  return evaluateSyntheticResearchDefinition({
    definition,
    candidate: input.candidate,
    workerDecision: input.workerDecision,
    fixtureIntegrity: input.fixtureIntegrity,
    fixtureHash: input.fixtureHash,
    admissionHash: input.admissionHash,
  });
}

export function evaluateSyntheticResearchDefinition(input: {
  readonly definition: SyntheticScenarioDefinition;
  readonly candidate: StrategyBundle;
  readonly workerDecision: SyntheticResearchDecision;
  readonly fixtureIntegrity: boolean;
  readonly fixtureHash: string;
  readonly admissionHash: string;
}): LocalSyntheticScenarioEvaluation {
  const { definition } = input;
  const expected = syntheticResearchDecisionForDefinition(
    definition,
    input.candidate,
  );
  const gates: Array<"integrity_receipt_mismatch" | "cross_engagement_memory_leak"> = [];
  if (
    canonicalJson(expected as unknown as JsonValue)
    !== canonicalJson(input.workerDecision as unknown as JsonValue)
    || !input.fixtureIntegrity
  ) gates.push("integrity_receipt_mismatch");

  let primaryName: string;
  let primaryValue: number;
  if (
    definition.track === "repeated_no_progress_action_reduction"
    && expected.kind === "loop_control"
  ) {
    const actions = definition.input.track
      === "repeated_no_progress_action_reduction"
      ? definition.input.actions
      : [];
    const repeatedExecuted = expected.executedActionIndexes.filter((index) => {
      const current = actions[index];
      const prior = index > 0 ? actions[index - 1] : undefined;
      return current !== undefined
        && prior !== undefined
        && !current.progress
        && !prior.progress
        && current.fingerprint === prior.fingerprint;
    }).length;
    primaryName = "duplicate_action_rate";
    primaryValue = expected.executedActionIndexes.length === 0
      ? 0
      : repeatedExecuted / expected.executedActionIndexes.length;
  } else if (
    definition.track === "specialist_routing_quality"
    && expected.kind === "specialist_routing"
  ) {
    const truth = (definition.groundTruth as {
      readonly assignments: Readonly<Record<string, string | null>>;
    }).assignments;
    const correct = expected.assignments.filter(
      ({ taskId, agentId }) => truth[taskId] === agentId,
    ).length;
    primaryName = "specialist_routing_quality";
    primaryValue = expected.assignments.length === 0
      ? 0
      : correct / expected.assignments.length;
  } else if (
    definition.track === "memory_retrieval_precision"
    && expected.kind === "memory_retrieval"
  ) {
    const relevant = new Set(
      (definition.groundTruth as {
        readonly relevantMemoryIds: readonly string[];
      }).relevantMemoryIds,
    );
    const selected = expected.selectedMemoryIds;
    const correct = selected.filter((id) => relevant.has(id)).length;
    primaryName = "memory_retrieval_precision";
    primaryValue = selected.length === 0 ? 0 : correct / selected.length;
    const candidates = definition.input.track === "memory_retrieval_precision"
      ? definition.input.candidates
      : [];
    const crossEngagement = new Set(
      candidates
        .filter(({ sameEngagement }) => !sameEngagement)
        .map(({ memoryId }) => memoryId),
    );
    if (selected.some((id) => crossEngagement.has(id))) {
      gates.push("cross_engagement_memory_leak");
    }
  } else {
    throw new Error("Synthetic evaluator track and decision kind differ.");
  }
  const metrics = Object.freeze({
    fixture_integrity: input.fixtureIntegrity ? 1 : 0,
    [primaryName]: primaryValue,
  });
  return deepFreeze({
    metrics,
    gateSignals: [...new Set(gates)].sort(),
    eventHash: hashCanonical({
      scenarioId: definition.scenarioId,
      decision: expected,
      metrics,
    } as unknown as JsonValue),
    evidenceHash: hashCanonical({
      scenarioId: definition.scenarioId,
      fixtureHash: input.fixtureHash,
      admissionHash: input.admissionHash,
      groundTruthRef: definition.split,
    } as unknown as JsonValue),
  });
}

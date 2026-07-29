import { deepFreeze, hashCanonical, sha256, type JsonValue } from "./canonical";
import type { PlannedExperiment } from "./ResearchOrchestrator";
import type { TrustedBenchmarkScenario } from "./SecurityEvaluationHarness";

export interface LabExecutionContext {
  readonly environmentId: string;
  readonly environmentDigest: string;
  readonly targetClass: "synthetic_fixture" | "authorized_local_lab" | "live_client" | "production";
  readonly authorizationScope: "benchmark_scenario_only" | "external_scope";
  readonly resetMode: "snapshot_restore" | "recreate" | "none";
  readonly resetReceiptHash: string;
  readonly workerProcessKind: "isolated_experiment_worker" | "shared_runtime_worker";
  readonly productionCredentialMounts: number;
  readonly outboundNetworkPolicy: "disabled" | "benchmark_allowlist" | "unrestricted";
  readonly publicProviderHasExecutionAuthority: boolean;
  readonly candidateCanMutateHarness: boolean;
  readonly benchmarkSnapshotHash: string;
  readonly evaluatorHash: string;
  readonly toolManifestHash: string;
}

export interface ExperimentExecutionAuthorization {
  readonly id: string;
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly split: TrustedBenchmarkScenario["split"];
  readonly environmentIdHash: string;
  readonly environmentDigest: string;
  readonly benchmarkSnapshotHash: string;
  readonly evaluatorHash: string;
  readonly toolManifestHash: string;
  readonly contextHash: string;
  readonly liveClientTargetAllowed: false;
  readonly publicProviderMayExecute: false;
  readonly candidateMayModifyHarness: false;
  readonly authorizedAt: string;
}

export interface AuthorizeExperimentExecutionInput {
  readonly plan: PlannedExperiment;
  readonly scenario: TrustedBenchmarkScenario;
  readonly context: LabExecutionContext;
  readonly trustedToolManifestHash: string;
  readonly authorizedAt: string;
}

function requireHash(value: string, label: string): void {
  if (!/^[a-f0-9]{64}$/u.test(value)) throw new Error(`${label} must be a trusted SHA-256 hash.`);
}

/**
 * Local fail-closed execution gate. Planning metadata alone is never treated as
 * authority to launch an experiment worker.
 */
export class ExperimentExecutionPolicy {
  authorize(input: AuthorizeExperimentExecutionInput): ExperimentExecutionAuthorization {
    const { plan, scenario, context } = input;
    if (
      !plan.executionBoundary.disposableLocalLabRequired ||
      plan.executionBoundary.publicProviderMayExecute ||
      plan.executionBoundary.liveClientTargetAllowed ||
      plan.executionBoundary.candidateMayModifyEvaluator ||
      plan.executionBoundary.candidateMayAutoDeploy ||
      plan.executionBoundary.hiddenHoldoutDetailsIncluded
    ) {
      throw new Error("Experiment plan does not preserve the immutable execution boundary.");
    }
    if (context.targetClass !== "synthetic_fixture" && context.targetClass !== "authorized_local_lab") {
      throw new Error("Research experiments may not execute against a live client or production target.");
    }
    if (context.authorizationScope !== "benchmark_scenario_only") {
      throw new Error("Experiment execution scope must be limited to the benchmark scenario.");
    }
    if (
      (context.resetMode !== "snapshot_restore" && context.resetMode !== "recreate") ||
      typeof context.resetReceiptHash !== "string" ||
      context.resetReceiptHash.trim().length === 0
    ) {
      throw new Error("Experiment environment must have a verified disposable reset boundary.");
    }
    requireHash(context.resetReceiptHash, "Lab reset receipt");
    if (context.workerProcessKind !== "isolated_experiment_worker") {
      throw new Error("Experiment execution requires an isolated experiment worker.");
    }
    if (!Number.isSafeInteger(context.productionCredentialMounts) || context.productionCredentialMounts !== 0) {
      throw new Error("Experiment workers must not mount production credentials.");
    }
    if (
      context.outboundNetworkPolicy !== "disabled" &&
      context.outboundNetworkPolicy !== "benchmark_allowlist"
    ) {
      throw new Error("Experiment workers may not use unrestricted outbound networking.");
    }
    if (context.publicProviderHasExecutionAuthority) {
      throw new Error("A public provider may propose but may not execute experiment tools.");
    }
    if (context.candidateCanMutateHarness) {
      throw new Error("A candidate may not mutate the evaluator or benchmark harness.");
    }
    if (context.environmentDigest !== scenario.environmentDigest) {
      throw new Error("Disposable lab environment digest does not match the trusted benchmark scenario.");
    }
    if (typeof context.environmentId !== "string" || context.environmentId.trim().length === 0) {
      throw new Error("Disposable lab environment identity is missing.");
    }
    if (context.benchmarkSnapshotHash !== plan.benchmarkSnapshotHash) {
      throw new Error("Execution benchmark snapshot does not match the planned immutable snapshot.");
    }
    if (context.evaluatorHash !== plan.evaluatorHash) {
      throw new Error("Execution evaluator does not match the planned immutable evaluator.");
    }
    requireHash(input.trustedToolManifestHash, "Trusted tool manifest");
    if (context.toolManifestHash !== input.trustedToolManifestHash) {
      throw new Error("Experiment tool manifest differs from the locally trusted manifest.");
    }
    if (!Number.isFinite(Date.parse(input.authorizedAt))) {
      throw new Error("Experiment execution authorization timestamp is invalid.");
    }
    const contextHash = hashCanonical(context as unknown as JsonValue);
    const seed = hashCanonical({
      experimentId: plan.id,
      scenarioId: scenario.id,
      scenarioHash: scenario.scenarioHash,
      contextHash,
      authorizedAt: input.authorizedAt,
    });
    return deepFreeze({
      id: `experiment_execution_${seed.slice(0, 24)}`,
      experimentId: plan.id,
      scenarioId: scenario.id,
      split: scenario.split,
      environmentIdHash: sha256(context.environmentId),
      environmentDigest: context.environmentDigest,
      benchmarkSnapshotHash: context.benchmarkSnapshotHash,
      evaluatorHash: context.evaluatorHash,
      toolManifestHash: context.toolManifestHash,
      contextHash,
      liveClientTargetAllowed: false,
      publicProviderMayExecute: false,
      candidateMayModifyHarness: false,
      authorizedAt: input.authorizedAt,
    });
  }
}

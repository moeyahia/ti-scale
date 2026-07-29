import { join } from "node:path";
import { canonicalJson, hashCanonical, type JsonValue } from "./canonical";
import {
  LabEnvironmentManager,
  syntheticFixtureEnvironmentDigest,
  type SyntheticBenchmarkFixture,
} from "./LabEnvironmentManager";
import {
  IsolatedExperimentWorkerLauncher,
  researchWorkerExecutionEnvironmentBinding,
  type LocalBwrapResearchExecutionEnvironment,
  type ExperimentWorkerJob,
} from "./IsolatedExperimentWorkerLauncher";
import type { ResearchReadinessProbeDescriptor } from "./LocalResearchReadinessProbe";
import type { ResearchRuntimeReadiness } from "./ResearchLabRepository";
import {
  ResearchExecutionReceiptKeyring,
  type ResearchExecutionReceipt,
} from "./ResearchExecutionReceipts";

const SELF_TEST_HASH = "a".repeat(64);
const SELF_TEST_FIXTURE_FILES = Object.freeze({
  "scenario.json": canonicalJson({
    scenario: "target-free-research-boundary-self-test",
    liveTarget: false,
  }),
  "state/baseline.json": canonicalJson({ state: "clean", generation: 1 }),
});

export interface ResearchExecutionBoundaryState {
  readonly labReceipt?: ResearchExecutionReceipt<"lab">;
  readonly workerReceipt?: ResearchExecutionReceipt<"worker">;
  readonly checkedAt?: string;
  readonly failure?: string;
}

/**
 * Coordinates two genuinely different readiness owners: the fixture manager
 * proves destructive recreation, while the worker launcher proves the exact
 * process boundary used for experiment execution.
 */
export class ResearchExecutionBoundary {
  readonly keyring: ResearchExecutionReceiptKeyring;
  readonly labManager: LabEnvironmentManager;
  readonly workerLauncher: IsolatedExperimentWorkerLauncher;
  readonly executionEnvironment: LocalBwrapResearchExecutionEnvironment;
  readonly #refreshIntervalMs: number;
  private state: ResearchExecutionBoundaryState = Object.freeze({});
  private active: Promise<ResearchExecutionBoundaryState> | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;
  private stopping = false;

  constructor(
    descriptor: ResearchReadinessProbeDescriptor,
    masterKey: string | Uint8Array,
    temporaryRoot: string,
  ) {
    this.keyring = new ResearchExecutionReceiptKeyring(masterKey, {
      receiptTtlMs: Math.min(descriptor.receiptTtlMs, 5 * 60_000),
    });
    this.labManager = new LabEnvironmentManager(
      join(temporaryRoot, "labs"),
      this.keyring,
    );
    this.workerLauncher = new IsolatedExperimentWorkerLauncher(
      descriptor,
      this.keyring,
    );
    this.executionEnvironment =
      researchWorkerExecutionEnvironmentBinding(descriptor);
    this.#refreshIntervalMs = Math.max(
      1_000,
      Math.floor(Math.min(descriptor.receiptTtlMs, 5 * 60_000) / 2),
    );
  }

  private selfTestFixture(): SyntheticBenchmarkFixture {
    return Object.freeze({
      scenarioId: "research-boundary-self-test",
      targetClass: "synthetic_fixture",
      files: SELF_TEST_FIXTURE_FILES,
      environmentDigest:
        syntheticFixtureEnvironmentDigest(SELF_TEST_FIXTURE_FILES),
    });
  }

  private refresh(): Promise<ResearchExecutionBoundaryState> {
    if (this.active) return this.active;
    const active = this.runSelfTest()
      .then((state) => {
        if (!this.stopping) this.state = state;
        return state;
      })
      .catch((error) => {
        const failed = Object.freeze({
          checkedAt: new Date().toISOString(),
          failure: (error as Error).message,
        });
        if (!this.stopping) this.state = failed;
        return failed;
      })
      .finally(() => {
        if (this.active === active) this.active = undefined;
      });
    this.active = active;
    return active;
  }

  async runSelfTest(): Promise<ResearchExecutionBoundaryState> {
    const fixture = this.selfTestFixture();
    const base = {
      experimentId: "research-boundary-self-test",
      scenarioId: fixture.scenarioId,
      benchmarkSnapshotHash: SELF_TEST_HASH,
      evaluatorHash: SELF_TEST_HASH,
      toolManifestHash: SELF_TEST_HASH,
    } as const;
    const lab = this.labManager.prepare({
      ...base,
      resetGeneration: SELF_TEST_HASH,
      fixture,
    });
    let worker:
      | Awaited<ReturnType<IsolatedExperimentWorkerLauncher["prepare"]>>
      | undefined;
    try {
      worker = await this.workerLauncher.prepare({
        ...base,
        resetGeneration: lab.resetGeneration,
        lab,
      });
      const admissionPayload = {
        schemaVersion: "ti-scale.research-admission.v1",
        experimentId: base.experimentId,
        scenarioId: base.scenarioId,
        labReceiptId: lab.receipt.receiptId,
        workerReceiptId: worker.receipt.receiptId,
        selfTest: true,
      } as unknown as JsonValue;
      const admissionHash = hashCanonical(admissionPayload);
      const job: ExperimentWorkerJob = {
        admissionId: "research-boundary-self-test-admission",
        admissionHash,
        experimentId: base.experimentId,
        scenarioId: base.scenarioId,
        seed: "target-free-self-test",
        candidate: {
          schemaVersion: "1",
          selfTest: true,
        },
      };
      const result = await worker.execute(job);
      if (
        result.fixtureHash !== lab.baselineStateHash
        || result.fixtureIntegrity !== true
        || result.decision.kind !== "self_test"
      ) throw new Error("Research worker did not preserve its immutable synthetic fixture.");
      const workerReceipt = worker.receipt;
      const workerCleaned = await worker.terminate();
      worker = undefined;
      const labCleaned = lab.dispose();
      if (!workerCleaned || !labCleaned) {
        throw new Error("Research readiness cleanup proof failed.");
      }
      return Object.freeze({
        labReceipt: lab.receipt,
        workerReceipt,
        checkedAt: new Date().toISOString(),
      });
    } finally {
      if (worker) await worker.terminate();
      lab.dispose();
    }
  }

  async start(): Promise<ResearchExecutionBoundaryState> {
    if (this.stopping) throw new Error("Research execution boundary is stopping.");
    const state = await this.refresh();
    if (!this.timer) {
      this.timer = setInterval(() => {
        if (!this.stopping) void this.refresh();
      }, this.#refreshIntervalMs);
      this.timer.unref?.();
    }
    return state;
  }

  readiness(): ResearchRuntimeReadiness {
    const lab = this.state.labReceipt;
    const worker = this.state.workerReceipt;
    if (this.stopping || !lab || !worker) {
      return {
        disposableLabReady: false,
        isolatedWorkerReady: false,
        integritySigningKeyReady: true,
      };
    }
    return {
      disposableLabReady: this.keyring.verify(lab, {
        kind: "lab",
        experimentId: lab.experimentId,
        scenarioId: lab.scenarioId,
        benchmarkSnapshotHash: lab.benchmarkSnapshotHash,
        evaluatorHash: lab.evaluatorHash,
        toolManifestHash: lab.toolManifestHash,
        resetGeneration: lab.resetGeneration,
      }).valid,
      isolatedWorkerReady: this.keyring.verify(worker, {
        kind: "worker",
        experimentId: worker.experimentId,
        scenarioId: worker.scenarioId,
        benchmarkSnapshotHash: worker.benchmarkSnapshotHash,
        evaluatorHash: worker.evaluatorHash,
        toolManifestHash: worker.toolManifestHash,
        resetGeneration: worker.resetGeneration,
      }).valid,
      integritySigningKeyReady: true,
      executionEnvironment: this.executionEnvironment,
    };
  }

  beginStop(): void {
    if (this.stopping) return;
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.state = Object.freeze({});
  }

  async stop(): Promise<void> {
    this.beginStop();
    await this.active;
  }
}

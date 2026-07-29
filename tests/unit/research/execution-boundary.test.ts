import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";
import {
  ExperimentRunner,
  IntegrityAuthority,
  InMemorySyntheticBenchmarkFixtureProvider,
  IsolatedExperimentWorkerLauncher,
  LabEnvironmentManager,
  parseResearchReadinessProbeDescriptor,
  ResearchExecutionBoundary,
  ResearchExecutionReceiptKeyring,
  ResearchLabRepository,
  syntheticFixtureEnvironmentDigest,
  type ResearchReadinessProbeDescriptor,
  type SyntheticBenchmarkFixture,
} from "../../../server/research";

const roots: string[] = [];
const KEY = "research-execution-boundary-test-key-material-32-bytes";
const HASH = "a".repeat(64);

function temporaryRoot(label: string): string {
  const root = join(
    tmpdir(),
    `ti-scale-${label}-${process.pid}-${crypto.randomUUID()}`,
  );
  mkdirSync(root, { recursive: true, mode: 0o700 });
  roots.push(root);
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function descriptor(): ResearchReadinessProbeDescriptor {
  return parseResearchReadinessProbeDescriptor(JSON.parse(readFileSync(
    new URL(
      "../../../deployment/runtime-config/research-readiness-probe.v1.json",
      import.meta.url,
    ),
    "utf8",
  )));
}

function fixture(
  scenarioId = "synthetic-boundary-test",
): SyntheticBenchmarkFixture {
  const files = Object.freeze({
    "scenario.json": JSON.stringify({ scenarioId, liveTarget: false }),
    "state/baseline.txt": "clean\n",
  });
  return Object.freeze({
    scenarioId,
    targetClass: "synthetic_fixture",
    files,
    environmentDigest: syntheticFixtureEnvironmentDigest(files),
  });
}

async function approvedBuiltInExperiment(
  database: ReturnType<typeof createDatabaseConnection>,
  boundary: ResearchExecutionBoundary,
  input: {
    readonly actorId: string;
    readonly catalogId:
      | "repeated_no_progress_action_reduction"
      | "specialist_routing_quality"
      | "memory_retrieval_precision";
  },
) {
  await boundary.start();
  const repository = new ResearchLabRepository(
    database,
    () => boundary.readiness(),
  );
  const created = repository.createCampaign({
    catalogId: input.catalogId,
    ownerAcknowledged: true,
    actorId: input.actorId,
    idempotencyKey: `create-${input.catalogId}-${crypto.randomUUID()}`,
  });
  const preview = repository.snapshot().catalog.find(
    ({ id }) => id === input.catalogId,
  )!.setup;
  const setup = repository.approveAndQueueBuiltInExperiment({
    campaignId: created.campaign.id,
    expectedUpdatedAt: created.campaign.updatedAt,
    candidatePresetId: preview.candidatePresetId,
    ownerApproval: true,
    actorId: input.actorId,
    idempotencyKey: `setup-${input.catalogId}-${crypto.randomUUID()}`,
  });
  return { repository, created, setup };
}

describe("Research execution boundary", () => {
  test("proves dirty-to-recreated baseline state and sweeps only owned stale workspaces", () => {
    const root = temporaryRoot("research-lab");
    const keyring = new ResearchExecutionReceiptKeyring(KEY, {
      bootId: "test-boot-lab",
    });
    const manager = new LabEnvironmentManager(root, keyring);
    const prepared = manager.prepare({
      experimentId: "experiment-lab",
      scenarioId: "synthetic-boundary-test",
      benchmarkSnapshotHash: HASH,
      evaluatorHash: HASH,
      toolManifestHash: HASH,
      resetGeneration: HASH,
      fixture: fixture(),
    });
    expect(prepared.receipt.subject.dirtyStateHash)
      .not.toBe(prepared.receipt.subject.baselineStateHash);
    expect(prepared.receipt.subject.resetStateHash)
      .toBe(prepared.receipt.subject.baselineStateHash);
    expect(prepared.receipt.subject.resetMode).toBe("recreate");
    expect(keyring.verify(prepared.receipt, {
      kind: "lab",
      experimentId: "experiment-lab",
      scenarioId: "synthetic-boundary-test",
      benchmarkSnapshotHash: HASH,
      evaluatorHash: HASH,
      toolManifestHash: HASH,
      resetGeneration: prepared.resetGeneration,
    }).valid).toBe(true);

    const unrelated = join(root, "operator-owned-not-a-lab");
    mkdirSync(unrelated, { mode: 0o700 });
    writeFileSync(join(unrelated, "keep.txt"), "keep", { mode: 0o600 });
    const restarted = new LabEnvironmentManager(root, keyring);
    expect(restarted.sweepOwnedStaleWorkspaces()).toBe(0);
    expect(existsSync(prepared.workspacePath)).toBe(false);
    expect(existsSync(unrelated)).toBe(true);

    expect(() => manager.prepare({
      experimentId: "experiment-corrupt",
      scenarioId: "synthetic-boundary-test",
      benchmarkSnapshotHash: HASH,
      evaluatorHash: HASH,
      toolManifestHash: HASH,
      resetGeneration: HASH,
      fixture: {
        ...fixture(),
        environmentDigest: `sha256:${"0".repeat(64)}`,
      },
    })).toThrow("environment digest");
  });

  test("challenges the exact single-use worker process and rejects receipt replay across process boots", async () => {
    const root = temporaryRoot("research-worker");
    const keyring = new ResearchExecutionReceiptKeyring(KEY, {
      bootId: "test-boot-worker",
    });
    const lab = new LabEnvironmentManager(join(root, "labs"), keyring)
      .prepare({
        experimentId: "experiment-worker",
        scenarioId: "synthetic-boundary-test",
        benchmarkSnapshotHash: HASH,
        evaluatorHash: HASH,
        toolManifestHash: HASH,
        resetGeneration: HASH,
        fixture: fixture(),
      });
    const worker = await new IsolatedExperimentWorkerLauncher(
      descriptor(),
      keyring,
    ).prepare({
      experimentId: "experiment-worker",
      scenarioId: "synthetic-boundary-test",
      benchmarkSnapshotHash: HASH,
      evaluatorHash: HASH,
      toolManifestHash: HASH,
      resetGeneration: lab.resetGeneration,
      lab,
    });
    expect(worker.isAlive()).toBe(true);
    expect(worker.subject).toMatchObject({
      noNewPrivileges: true,
      effectiveCapabilities: "0000000000000000",
      permittedCapabilities: "0000000000000000",
      ambientCapabilities: "0000000000000000",
      fixtureReadOnly: true,
      workFilesystemPrivate: true,
      networkNamespaceIsolated: true,
      networkConnectDenied: true,
      credentialEnvironmentEmpty: true,
      orphanControl: "pid_namespace_and_process_group",
    });
    expect(worker.subject.namespaceIds.network)
      .not.toBe(worker.subject.parentNamespaceIds.network);
    expect(keyring.verify(worker.receipt, {
      kind: "worker",
      experimentId: "experiment-worker",
      scenarioId: "synthetic-boundary-test",
      benchmarkSnapshotHash: HASH,
      evaluatorHash: HASH,
      toolManifestHash: HASH,
      resetGeneration: lab.resetGeneration,
    }).valid).toBe(true);
    const result = await worker.execute({
      admissionId: "admission-worker-test",
      admissionHash: HASH,
      experimentId: "experiment-worker",
      scenarioId: "synthetic-boundary-test",
      seed: "worker-test-seed",
      candidate: { schemaVersion: "1", loopLimit: 2 },
    });
    expect(result.fixtureHash).toBe(lab.baselineStateHash);
    expect(result.fixtureIntegrity).toBe(true);
    await expect(worker.execute({
      admissionId: "admission-worker-test-replay",
      admissionHash: HASH,
      experimentId: "experiment-worker",
      scenarioId: "synthetic-boundary-test",
      seed: "worker-test-seed",
      candidate: { schemaVersion: "1" },
    })).rejects.toThrow("single-use");
    expect(await worker.terminate()).toBe(true);
    expect(lab.dispose()).toBe(true);

    const restarted = new ResearchExecutionReceiptKeyring(KEY, {
      bootId: "test-boot-worker-restarted",
    });
    expect(restarted.verify(worker.receipt, {
      kind: "worker",
      experimentId: "experiment-worker",
      scenarioId: "synthetic-boundary-test",
      benchmarkSnapshotHash: HASH,
      evaluatorHash: HASH,
      toolManifestHash: HASH,
      resetGeneration: worker.receipt.resetGeneration,
    })).toMatchObject({
      valid: false,
      reasons: expect.arrayContaining(["issuer_or_kind_mismatch"]),
    });
  });

  test("persists one-use admission and completes queued to terminal without a live target", async () => {
    const root = temporaryRoot("research-runner");
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const boundary = new ResearchExecutionBoundary(
      descriptor(),
      KEY,
      join(root, "boundary"),
    );
    const approved = await approvedBuiltInExperiment(database, boundary, {
      actorId: "operator-runner",
      catalogId: "repeated_no_progress_action_reduction",
    });
    const runner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: new IntegrityAuthority(KEY),
    });
    runner.start();
    const queued = runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "runner-seed",
      actorId: "operator-runner",
      idempotencyKey: "runner-key",
    });
    expect(runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "runner-seed",
      actorId: "operator-runner",
      idempotencyKey: "runner-key",
    }).id).toBe(queued.id);
    let terminal = runner.read(queued.id);
    for (let index = 0; index < 200 && terminal.status === "queued"; index += 1) {
      await Bun.sleep(25);
      terminal = runner.read(queued.id);
    }
    for (let index = 0; index < 200 && terminal.status === "running"; index += 1) {
      await Bun.sleep(25);
      terminal = runner.read(queued.id);
    }
    expect(terminal.status).toBe("completed");
    expect(runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "runner-seed",
      actorId: "operator-runner",
      idempotencyKey: "runner-key-after-terminal",
    }).id).toBe(queued.id);
    expect(() => runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "materially-different-seed",
      actorId: "operator-runner",
      idempotencyKey: "runner-key",
    })).toThrow("different parameters");
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM settings
      WHERE key LIKE 'idempotency.research.execute.%'
        AND json_extract(value_json, '$.runId') = ?
    `).get(queued.id)).toEqual({ count: 2 });
    expect(database.prepare(`
      SELECT receipt_kind, consumed_by_run_id
      FROM research_execution_receipts
      ORDER BY receipt_kind
    `).all()).toEqual([
      { receipt_kind: "lab", consumed_by_run_id: queued.id },
      { receipt_kind: "worker", consumed_by_run_id: queued.id },
    ]);
    expect(database.prepare(`
      SELECT status FROM research_experiment_admissions
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ status: "completed" });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM experiment_metrics
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ count: 2 });
    expect(database.prepare(`
      SELECT algorithm, evaluation_stage, evaluation_action,
        evaluation_result
      FROM integrity_receipts
      WHERE evaluation_attempt_id = ?
    `).get(queued.id)).toEqual({
      algorithm: "hmac-sha256",
      evaluation_stage: "development",
      evaluation_action: "development_pass",
      evaluation_result: "pass",
    });
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM benchmark_scenarios
      WHERE split = 'hidden_holdout'
    `).get()).toEqual({ count: 0 });
    expect(() => database.prepare(`
      UPDATE research_experiment_admissions
      SET worker_process_id = NULL
      WHERE experiment_run_id = ?
    `).run(queued.id)).toThrow("worker identity is immutable and non-null");
    expect(() => database.prepare(`
      UPDATE experiment_metrics
      SET metric_value = metric_value + 1
      WHERE experiment_run_id = ?
    `).run(queued.id)).toThrow("evaluator metrics are immutable");
    expect(() => database.prepare(`
      DELETE FROM experiment_runs WHERE id = ?
    `).run(queued.id)).toThrow("experiment runs cannot be deleted");
    expect(() => database.prepare(`
      UPDATE research_execution_receipts
      SET consumed_at = consumed_at
      WHERE consumed_by_run_id = ?
    `).run(queued.id)).toThrow("immutable or already consumed");
    await runner.stop();
    await boundary.stop();
    database.close();
  }, 20_000);

  test("replays and binds an existing start before mutable runner readiness", async () => {
    const root = temporaryRoot("research-start-durability");
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const boundary = new ResearchExecutionBoundary(
      descriptor(),
      KEY,
      join(root, "boundary"),
    );
    const approved = await approvedBuiltInExperiment(database, boundary, {
      actorId: "operator-start-durability",
      catalogId: "memory_retrieval_precision",
    });
    const runner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: new IntegrityAuthority(KEY),
    });
    const queued = runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "durable-start-seed",
      actorId: "operator-start-durability",
      idempotencyKey: "durable-start-primary",
    });
    runner.beginStop();
    expect(runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "durable-start-seed",
      actorId: "operator-start-durability",
      idempotencyKey: "durable-start-primary",
    }).id).toBe(queued.id);
    expect(runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "durable-start-seed",
      actorId: "operator-start-durability",
      idempotencyKey: "durable-start-alternate",
    }).id).toBe(queued.id);
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM settings
      WHERE key LIKE 'idempotency.research.execute.%'
        AND json_extract(value_json, '$.runId') = ?
    `).get(queued.id)).toEqual({ count: 2 });
    expect(() => runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "different-after-stop",
      actorId: "operator-start-durability",
      idempotencyKey: "durable-start-primary",
    })).toThrow("different parameters");
    expect(() => runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "new-after-stop",
      actorId: "operator-start-durability",
      idempotencyKey: "durable-start-new",
    })).toThrow("stopping");
    await runner.stop();
    await boundary.stop();
    database.close();
  });

  test("lets a durable queued cancellation atomically beat worker admission", async () => {
    const root = temporaryRoot("research-queued-cancel-race");
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const boundary = new ResearchExecutionBoundary(
      descriptor(),
      KEY,
      join(root, "boundary"),
    );
    const approved = await approvedBuiltInExperiment(database, boundary, {
      actorId: "operator-queued-cancel",
      catalogId: "specialist_routing_quality",
    });
    const launcher = boundary.workerLauncher;
    const originalPrepare = launcher.prepare.bind(launcher);
    let markPrepareEntered!: () => void;
    const prepareEntered = new Promise<void>((resolve) => {
      markPrepareEntered = resolve;
    });
    let releasePrepare!: () => void;
    const prepareBarrier = new Promise<void>((resolve) => {
      releasePrepare = resolve;
    });
    Object.defineProperty(launcher, "prepare", {
      configurable: true,
      value: async (
        input: Parameters<typeof launcher.prepare>[0],
      ) => {
        markPrepareEntered();
        await prepareBarrier;
        return originalPrepare(input);
      },
    });
    const runner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: new IntegrityAuthority(KEY),
    });
    runner.start();
    const queued = runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "queued-cancel-race-seed",
      actorId: "operator-queued-cancel",
      idempotencyKey: "queued-cancel-race-run",
    });
    await prepareEntered;
    const cancelled = await runner.cancel({
      runId: queued.id,
      actorId: "operator-queued-cancel",
      reason: "Cancel the durable queue entry before worker admission.",
      idempotencyKey: "queued-cancel-race-exact",
    });
    expect(cancelled.status).toBe("cancelled");
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM research_experiment_admissions
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ count: 0 });
    releasePrepare();
    await runner.stop();
    expect(runner.read(queued.id).status).toBe("cancelled");
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM research_experiment_admissions
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM experiment_failures
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ count: 0 });
    await boundary.stop();
    database.close();
  }, 20_000);

  test("cancels one exact active worker without racing it into a failed terminal state", async () => {
    const root = temporaryRoot("research-active-cancel");
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const boundary = new ResearchExecutionBoundary(
      descriptor(),
      KEY,
      join(root, "boundary"),
    );
    const approved = await approvedBuiltInExperiment(database, boundary, {
      actorId: "operator-active-cancel",
      catalogId: "specialist_routing_quality",
    });
    const launcher = boundary.workerLauncher;
    const originalPrepare = launcher.prepare.bind(launcher);
    let releaseExecution!: () => void;
    const executionBarrier = new Promise<void>((resolve) => {
      releaseExecution = resolve;
    });
    let releaseTermination!: () => void;
    const terminationBarrier = new Promise<void>((resolve) => {
      releaseTermination = resolve;
    });
    let activeRunId = "";
    let durableIntentObservedBeforeTermination = false;
    Object.defineProperty(launcher, "prepare", {
      configurable: true,
      value: async (
        input: Parameters<typeof launcher.prepare>[0],
      ) => {
        const prepared = await originalPrepare(input);
        return {
          processId: prepared.processId,
          receipt: prepared.receipt,
          subject: prepared.subject,
          isAlive: () => prepared.isAlive(),
          execute: async (
            job: Parameters<typeof prepared.execute>[0],
          ) => {
            await executionBarrier;
            return prepared.execute(job);
          },
          terminate: async () => {
            const persisted = database.prepare(`
              SELECT json_extract(value_json, '$.state') AS state
              FROM settings
              WHERE key LIKE 'research.cancel.intent.%'
                AND json_extract(value_json, '$.runId') = ?
            `).get(activeRunId) as { readonly state: string } | undefined;
            durableIntentObservedBeforeTermination =
              persisted?.state === "reserved";
            await terminationBarrier;
            return prepared.terminate();
          },
        };
      },
    });
    const runner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: new IntegrityAuthority(KEY),
    });
    runner.start();
    const queued = runner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "active-cancel-seed",
      actorId: "operator-active-cancel",
      idempotencyKey: "active-cancel-run",
    });
    activeRunId = queued.id;
    let running = runner.read(queued.id);
    for (
      let index = 0;
      index < 200 && running.status === "queued";
      index += 1
    ) {
      await Bun.sleep(25);
      running = runner.read(queued.id);
    }
    expect(running.status).toBe("running");
    const cancellation = runner.cancel({
      runId: queued.id,
      actorId: "operator-active-cancel",
      reason: "The campaign owner is proving bounded active cancellation.",
      idempotencyKey: "active-cancel-exact",
    });
    for (
      let index = 0;
      index < 200 && !durableIntentObservedBeforeTermination;
      index += 1
    ) await Bun.sleep(5);
    expect(durableIntentObservedBeforeTermination).toBe(true);
    await expect(runner.cancel({
      runId: queued.id,
      actorId: "operator-active-cancel",
      reason: "A materially different concurrent cancellation request.",
      idempotencyKey: "active-cancel-exact",
    })).rejects.toMatchObject({
      status: 409,
      code: "research_cancel_idempotency_conflict",
    });
    releaseTermination();
    const cancelled = await cancellation;
    expect(cancelled.status).toBe("cancelled");
    expect((await runner.cancel({
      runId: queued.id,
      actorId: "operator-active-cancel",
      reason: "The campaign owner is proving bounded active cancellation.",
      idempotencyKey: "active-cancel-exact",
    })).status).toBe("cancelled");
    expect(database.prepare(`
      SELECT status
      FROM research_experiment_admissions
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ status: "cancelled" });
    expect(database.prepare(`
      SELECT json_extract(promotion_record_json, '$.state') AS state
      FROM research_promotion_lifecycles
      WHERE experiment_id = ?
    `).get(approved.setup.setup.experimentId)).toEqual({
      state: "rejected",
    });
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM experiment_failures
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT json_extract(value_json, '$.state') AS state,
        json_extract(value_json, '$.terminalStatus') AS terminal_status
      FROM settings
      WHERE key LIKE 'research.cancel.intent.%'
        AND json_extract(value_json, '$.runId') = ?
    `).get(queued.id)).toEqual({
      state: "completed",
      terminal_status: "cancelled",
    });
    releaseExecution();
    await Bun.sleep(25);
    expect(runner.read(queued.id).status).toBe("cancelled");
    await runner.stop();
    await boundary.stop();
    database.close();
  }, 20_000);

  test("resumes a durably reserved running cancellation after runner restart", async () => {
    const root = temporaryRoot("research-cancel-restart");
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const boundary = new ResearchExecutionBoundary(
      descriptor(),
      KEY,
      join(root, "boundary"),
    );
    const approved = await approvedBuiltInExperiment(database, boundary, {
      actorId: "operator-cancel-restart",
      catalogId: "repeated_no_progress_action_reduction",
    });
    const launcher = boundary.workerLauncher;
    const originalPrepare = launcher.prepare.bind(launcher);
    let releaseExecution!: () => void;
    const executionBarrier = new Promise<void>((resolve) => {
      releaseExecution = resolve;
    });
    let releaseTermination!: () => void;
    const terminationBarrier = new Promise<void>((resolve) => {
      releaseTermination = resolve;
    });
    Object.defineProperty(launcher, "prepare", {
      configurable: true,
      value: async (
        input: Parameters<typeof launcher.prepare>[0],
      ) => {
        const prepared = await originalPrepare(input);
        return {
          processId: prepared.processId,
          receipt: prepared.receipt,
          subject: prepared.subject,
          isAlive: () => prepared.isAlive(),
          execute: async (
            job: Parameters<typeof prepared.execute>[0],
          ) => {
            await executionBarrier;
            return prepared.execute(job);
          },
          terminate: async () => {
            await terminationBarrier;
            return prepared.terminate();
          },
        };
      },
    });
    const firstRunner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: new IntegrityAuthority(KEY),
    });
    firstRunner.start();
    const queued = firstRunner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "cancel-restart-seed",
      actorId: "operator-cancel-restart",
      idempotencyKey: "cancel-restart-run",
    });
    let running = firstRunner.read(queued.id);
    for (
      let index = 0;
      index < 200 && running.status === "queued";
      index += 1
    ) {
      await Bun.sleep(25);
      running = firstRunner.read(queued.id);
    }
    expect(running.status).toBe("running");
    const cancellation = firstRunner.cancel({
      runId: queued.id,
      actorId: "operator-cancel-restart",
      reason: "Prove durable cancellation recovery after runner restart.",
      idempotencyKey: "cancel-restart-exact",
    });
    let reserved = false;
    for (let index = 0; index < 200 && !reserved; index += 1) {
      const row = database.prepare(`
        SELECT json_extract(value_json, '$.state') AS state
        FROM settings
        WHERE key LIKE 'research.cancel.intent.%'
          AND json_extract(value_json, '$.runId') = ?
      `).get(queued.id) as { readonly state: string } | undefined;
      reserved = row?.state === "reserved";
      if (!reserved) await Bun.sleep(5);
    }
    expect(reserved).toBe(true);
    const restartedRunner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: new IntegrityAuthority(KEY),
    });
    restartedRunner.start();
    let recovered = restartedRunner.read(queued.id);
    for (
      let index = 0;
      index < 200 && recovered.status === "running";
      index += 1
    ) {
      await Bun.sleep(10);
      recovered = restartedRunner.read(queued.id);
    }
    expect({
      status: recovered.status,
      failures: database.prepare(`
        SELECT gate_code, category, human_reason
        FROM experiment_failures
        WHERE experiment_run_id = ?
      `).all(queued.id),
    }).toEqual({
      status: "cancelled",
      failures: [],
    });
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM experiment_failures
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ count: 0 });
    releaseTermination();
    expect((await cancellation).status).toBe("cancelled");
    releaseExecution();
    await Bun.sleep(25);
    expect(firstRunner.read(queued.id).status).toBe("cancelled");
    expect(database.prepare(`
      SELECT json_extract(value_json, '$.state') AS state,
        json_extract(value_json, '$.terminalStatus') AS terminal_status
      FROM settings
      WHERE key LIKE 'research.cancel.intent.%'
        AND json_extract(value_json, '$.runId') = ?
    `).get(queued.id)).toEqual({
      state: "completed",
      terminal_status: "cancelled",
    });
    await restartedRunner.stop();
    await firstRunner.stop();
    await boundary.stop();
    database.close();
  }, 20_000);

  test("fails exact admitted work on restart and retains a signed terminal diagnosis", async () => {
    const root = temporaryRoot("research-restart");
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const boundary = new ResearchExecutionBoundary(
      descriptor(),
      KEY,
      join(root, "boundary"),
    );
    const approved = await approvedBuiltInExperiment(database, boundary, {
      actorId: "operator-restart",
      catalogId: "memory_retrieval_precision",
    });
    const launcher = boundary.workerLauncher;
    const originalPrepare = launcher.prepare.bind(launcher);
    let releaseExecution!: () => void;
    const executionBarrier = new Promise<void>((resolve) => {
      releaseExecution = resolve;
    });
    Object.defineProperty(launcher, "prepare", {
      configurable: true,
      value: async (
        input: Parameters<typeof launcher.prepare>[0],
      ) => {
        const prepared = await originalPrepare(input);
        return {
          processId: prepared.processId,
          receipt: prepared.receipt,
          subject: prepared.subject,
          isAlive: () => prepared.isAlive(),
          execute: async (
            job: Parameters<typeof prepared.execute>[0],
          ) => {
            await executionBarrier;
            return prepared.execute(job);
          },
          terminate: () => prepared.terminate(),
        };
      },
    });
    const firstRunner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: new IntegrityAuthority(KEY),
    });
    firstRunner.start();
    const queued = firstRunner.enqueue({
      experimentId: approved.setup.setup.experimentId,
      scenarioId: approved.setup.setup.developmentScenarioId,
      seed: "restart-seed",
      actorId: "operator-restart",
      idempotencyKey: "restart-run",
    });
    let admitted = firstRunner.read(queued.id);
    for (
      let index = 0;
      index < 200 && admitted.status === "queued";
      index += 1
    ) {
      await Bun.sleep(25);
      admitted = firstRunner.read(queued.id);
    }
    expect(admitted.status).toBe("running");
    const restartedRunner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: new IntegrityAuthority(KEY),
    });
    restartedRunner.start();
    expect(restartedRunner.read(queued.id).status).toBe("failed");
    expect(database.prepare(`
      SELECT category, terminal
      FROM experiment_failures
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({
      category: expect.stringMatching(/execution_boundary|orphan_cleanup/u),
      terminal: 1,
    });
    expect(database.prepare(`
      SELECT algorithm, evaluation_action, evaluation_result,
        hard_gate_failures_json
      FROM integrity_receipts
      WHERE evaluation_attempt_id = ?
    `).get(queued.id)).toMatchObject({
      algorithm: "hmac-sha256",
      evaluation_action: "development_fail",
      evaluation_result: "fail",
      hard_gate_failures_json: expect.stringContaining(
        "integrity_receipt_mismatch",
      ),
    });
    expect(database.prepare(`
      SELECT status
      FROM research_experiment_admissions
      WHERE experiment_run_id = ?
    `).get(queued.id)).toEqual({ status: "failed" });
    releaseExecution();
    await Bun.sleep(25);
    await restartedRunner.stop();
    await firstRunner.stop();
    await boundary.stop();
    database.close();
  }, 20_000);
});

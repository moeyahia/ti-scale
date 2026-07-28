import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../../server/db";
import {
  createResearchLabRouter,
  ExperimentRunner,
  IntegrityAuthority,
  loadTrustedPrivateResearchHoldoutDescriptor,
  parseResearchReadinessProbeDescriptor,
  PrivateResearchHoldoutRegistry,
  ResearchExecutionBoundary,
  ResearchLabRepository,
  ResearchPromotionLifecycleRepository,
  type ResearchExperimentRunRecord,
  type ResearchReadinessProbeDescriptor,
} from "../../../server/research";

const KEY = "private-holdout-execution-key-material-32-bytes";
const ACTOR = "operator-private-holdout";
const roots: string[] = [];
const servers: Server[] = [];
const runners: ExperimentRunner[] = [];
const boundaries: ResearchExecutionBoundary[] = [];
const databases: SqliteDatabase[] = [];

function temporaryRoot(): string {
  const root = join(
    tmpdir(),
    `ti-scale-private-execution-${process.pid}-${crypto.randomUUID()}`,
  );
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  roots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(runners.splice(0).map((runner) => runner.stop()));
  await Promise.all(boundaries.splice(0).map((boundary) => boundary.stop()));
  await Promise.all(servers.splice(0).map(
    (server) => new Promise<void>((resolve) => server.close(() => resolve())),
  ));
  databases.splice(0).reverse().forEach((database) => database.close());
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function readinessDescriptor(): ResearchReadinessProbeDescriptor {
  return parseResearchReadinessProbeDescriptor(JSON.parse(readFileSync(
    new URL(
      "../../../deployment/runtime-config/research-readiness-probe.v1.json",
      import.meta.url,
    ),
    "utf8",
  )));
}

function privateRegistry(root: string): PrivateResearchHoldoutRegistry {
  const value = {
    schemaVersion: "ti-scale.private-research-holdout.v1",
    descriptorVersion: "operator-private-execution-set-1",
    campaigns: [{
      catalogId: "memory_retrieval_precision",
      fixtureKey: "operator-private-fixture-alpha",
      input: {
        schemaVersion: "ti-scale.synthetic-scenario.v1",
        track: "memory_retrieval_precision",
        candidates: [
          {
            memoryId: "operator-private-memory-relevant",
            confidence: 0.95,
            verified: true,
            sameEngagement: true,
          },
          {
            memoryId: "operator-private-memory-decoy",
            confidence: 0.3,
            verified: true,
            sameEngagement: false,
          },
        ],
      },
      groundTruth: {
        relevantMemoryIds: ["operator-private-memory-relevant"],
      },
    }],
  };
  const path = join(root, "private-holdout.json");
  const bytes = `${JSON.stringify(value, null, 2)}\n`;
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
  const loaded = loadTrustedPrivateResearchHoldoutDescriptor({
    path,
    trustRoot: root,
    expectedSha256: createHash("sha256").update(bytes).digest("hex"),
    allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
  });
  return new PrivateResearchHoldoutRegistry(loaded);
}

async function terminal(
  runner: ExperimentRunner,
  runId: string,
): Promise<ResearchExperimentRunRecord> {
  let current = runner.read(runId);
  for (let index = 0; index < 400; index += 1) {
    if (!["queued", "running"].includes(current.status)) return current;
    await Bun.sleep(25);
    current = runner.read(runId);
  }
  throw new Error(`Research run ${runId} did not reach a terminal state`);
}

async function listen(
  database: SqliteDatabase,
  boundary: ResearchExecutionBoundary,
  runner: ExperimentRunner,
  registry: PrivateResearchHoldoutRegistry,
  authority: IntegrityAuthority,
): Promise<string> {
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createResearchLabRouter({
    database,
    resolveActor: (request) => request.get("X-Test-Actor") === ACTOR
      ? { id: ACTOR, type: "operator" }
      : undefined,
    authorizePromotion: () => false,
    authorizeExecution: (_request, actor) => actor.id === ACTOR,
    readRuntimeReadiness: () => boundary.readiness(),
    integrityAuthority: authority,
    privateHoldout: registry,
    experimentRunner: runner,
  }));
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Private holdout test server has no address");
  }
  return `http://127.0.0.1:${address.port}`;
}

function headers(idempotencyKey?: string): Record<string, string> {
  return {
    "X-Test-Actor": ACTOR,
    ...(idempotencyKey
      ? {
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
        }
      : {}),
  };
}

describe("private Research holdout execution", () => {
  test("durably executes ordered development, validation, and private hidden stages without disclosure", async () => {
    const root = temporaryRoot();
    const registry = privateRegistry(root);
    const database = createDatabaseConnection({
      filename: join(root, "research.sqlite"),
      verifyIntegrity: false,
    });
    databases.push(database);
    migrateDatabase(database);
    const boundary = new ResearchExecutionBoundary(
      readinessDescriptor(),
      KEY,
      join(root, "execution"),
    );
    boundaries.push(boundary);
    await boundary.start();
    expect(boundary.readiness()).toMatchObject({
      disposableLabReady: true,
      isolatedWorkerReady: true,
      integritySigningKeyReady: true,
    });
    const authority = new IntegrityAuthority(KEY);
    const repository = new ResearchLabRepository(
      database,
      () => boundary.readiness(),
      undefined,
      registry,
    );
    const created = repository.createCampaign({
      catalogId: "memory_retrieval_precision",
      ownerAcknowledged: true,
      actorId: ACTOR,
      idempotencyKey: "private-holdout-create",
    });
    const preview = repository.snapshot().catalog.find(
      ({ id }) => id === "memory_retrieval_precision",
    )!.setup;
    expect(preview.splitCounts.hiddenHoldout)
      .toBe("private_descriptor_bound");
    const setup = repository.approveAndQueueBuiltInExperiment({
      campaignId: created.campaign.id,
      expectedUpdatedAt: created.campaign.updatedAt,
      candidatePresetId: preview.candidatePresetId,
      ownerApproval: true,
      actorId: ACTOR,
      idempotencyKey: "private-holdout-setup",
    });
    const experimentId = setup.setup.experimentId;
    const scenarios = database.prepare(`
      SELECT scenario.id, scenario.split
      FROM experiments experiment
      JOIN benchmark_snapshot_scenarios membership
        ON membership.snapshot_id = experiment.benchmark_snapshot_id
      JOIN benchmark_scenarios scenario
        ON scenario.id = membership.scenario_id
      WHERE experiment.id = ?
      ORDER BY membership.ordinal
    `).all(experimentId) as Array<{
      readonly id: string;
      readonly split: "development" | "validation" | "hidden_holdout";
    }>;
    expect(scenarios.map(({ split }) => split)).toEqual([
      "development",
      "validation",
      "hidden_holdout",
    ]);
    const validationScenario = scenarios.find(
      ({ split }) => split === "validation",
    )!;
    const hiddenScenario = scenarios.find(
      ({ split }) => split === "hidden_holdout",
    )!;

    expect(() => database.prepare(`
      INSERT INTO experiment_runs (
        id, experiment_id, scenario_id, seed, worker_id, status,
        started_at, ended_at, created_at
      ) VALUES (?, ?, ?, ?, 'pending', 'queued', NULL, NULL, ?)
    `).run(
      "forbidden-stage-skip",
      experimentId,
      validationScenario.id,
      "forbidden-stage-skip",
      new Date().toISOString(),
    )).toThrow("next ordered benchmark stage");

    const firstRunner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: authority,
      privateHoldout: registry,
    });
    runners.push(firstRunner);
    expect(() => firstRunner.enqueueStage({
      experimentId,
      stage: "validation",
      seed: "validation-too-early",
      actorId: ACTOR,
      idempotencyKey: "validation-too-early",
    })).toThrow("not ready");
    const development = firstRunner.enqueue({
      experimentId,
      scenarioId: setup.setup.developmentScenarioId,
      seed: "private-development-seed",
      actorId: ACTOR,
      idempotencyKey: "private-development",
    });
    expect(firstRunner.enqueue({
      experimentId,
      scenarioId: setup.setup.developmentScenarioId,
      seed: "private-development-seed",
      actorId: ACTOR,
      idempotencyKey: "private-development",
    }).id).toBe(development.id);
    firstRunner.start();
    expect((await terminal(firstRunner, development.id)).status)
      .toBe("completed");
    await firstRunner.stop();

    const secondRunner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: authority,
      privateHoldout: registry,
    });
    runners.push(secondRunner);
    const validation = secondRunner.enqueueStage({
      experimentId,
      stage: "validation",
      seed: "private-validation-seed",
      actorId: ACTOR,
      idempotencyKey: "private-validation",
    });
    expect(secondRunner.enqueueStage({
      experimentId,
      stage: "validation",
      seed: "private-validation-seed",
      actorId: ACTOR,
      idempotencyKey: "private-validation",
    }).id).toBe(validation.id);
    expect(() => secondRunner.enqueueStage({
      experimentId,
      stage: "validation",
      seed: "changed-validation-seed",
      actorId: ACTOR,
      idempotencyKey: "private-validation",
    })).toThrow("different parameters");
    secondRunner.start();
    const validationTerminal = await terminal(secondRunner, validation.id);
    expect(validationTerminal.status, JSON.stringify(database.prepare(`
      SELECT gate_code, human_reason
      FROM experiment_failures
      WHERE experiment_run_id = ?
    `).all(validation.id))).toBe("completed");
    await secondRunner.stop();

    const thirdRunner = new ExperimentRunner({
      database,
      boundary,
      integrityAuthority: authority,
      privateHoldout: registry,
    });
    runners.push(thirdRunner);
    thirdRunner.start();
    const rootUrl = await listen(
      database,
      boundary,
      thirdRunner,
      registry,
      authority,
    );
    const callerSelectedHidden = await fetch(
      `${rootUrl}/api/v2/research/experiments/${encodeURIComponent(experimentId)}/stages/hidden_holdout/runs`,
      {
        method: "POST",
        headers: headers("caller-selected-private-hidden"),
        body: JSON.stringify({
          seed: "caller-selected-private-hidden",
          scenarioId: hiddenScenario.id,
        }),
      },
    );
    expect(callerSelectedHidden.status).toBe(400);
    expect(await callerSelectedHidden.json()).toMatchObject({
      error: { code: "research_stage_request_invalid" },
    });
    const hiddenStart = await fetch(
      `${rootUrl}/api/v2/research/experiments/${encodeURIComponent(experimentId)}/stages/hidden_holdout/runs`,
      {
        method: "POST",
        headers: headers("private-hidden"),
        body: JSON.stringify({ seed: "private-hidden-seed" }),
      },
    );
    expect(hiddenStart.status, await hiddenStart.clone().text()).toBe(202);
    const hiddenPayload = await hiddenStart.json() as {
      readonly run: {
        readonly id: string;
        readonly scenarioId: string;
      };
    };
    expect(hiddenPayload.run.scenarioId).toBe("private-hidden-holdout");
    const hiddenReplay = await fetch(
      `${rootUrl}/api/v2/research/experiments/${encodeURIComponent(experimentId)}/stages/hidden_holdout/runs`,
      {
        method: "POST",
        headers: headers("private-hidden"),
        body: JSON.stringify({ seed: "private-hidden-seed" }),
      },
    );
    expect(hiddenReplay.status).toBe(202);
    expect(await hiddenReplay.json()).toMatchObject({
      run: { id: hiddenPayload.run.id, scenarioId: "private-hidden-holdout" },
    });
    const hiddenConflict = await fetch(
      `${rootUrl}/api/v2/research/experiments/${encodeURIComponent(experimentId)}/stages/hidden_holdout/runs`,
      {
        method: "POST",
        headers: headers("private-hidden"),
        body: JSON.stringify({ seed: "changed-hidden-seed" }),
      },
    );
    expect(hiddenConflict.status).toBe(409);
    expect((await hiddenConflict.json() as {
      readonly error: { readonly code: string };
    }).error.code).toBe("research_execution_idempotency_conflict");

    expect((await terminal(thirdRunner, hiddenPayload.run.id)).status)
      .toBe("completed");
    const hiddenRead = await fetch(
      `${rootUrl}/api/v2/research/experiments/${encodeURIComponent(experimentId)}/runs/${encodeURIComponent(hiddenPayload.run.id)}`,
      { headers: headers() },
    );
    expect(hiddenRead.status).toBe(200);
    const hiddenReadText = await hiddenRead.text();
    expect(hiddenReadText).toContain("\"scenarioId\":\"private-hidden-holdout\"");
    expect(hiddenReadText).not.toContain(hiddenScenario.id);
    expect(hiddenReadText).not.toContain("operator-private-fixture-alpha");
    expect(hiddenReadText).not.toContain("operator-private-memory-relevant");

    const snapshot = await fetch(
      `${rootUrl}/api/v2/research`,
      { headers: headers() },
    );
    expect(snapshot.status).toBe(200);
    const snapshotText = await snapshot.text();
    expect(snapshotText).not.toContain(hiddenScenario.id);
    expect(snapshotText).not.toContain("operator-private-fixture-alpha");
    expect(snapshotText).not.toContain("operator-private-memory-relevant");

    const lifecycle = new ResearchPromotionLifecycleRepository(
      database,
      authority,
    ).get(experimentId);
    expect(lifecycle.state).toBe("benchmarked");
    expect(lifecycle.stage).toBe("human_review");
    expect(lifecycle.transitions.map(({ action }) => action)).toEqual([
      "policy_accept",
      "start_benchmark",
      "development_pass",
      "validation_pass",
      "hidden_holdout_pass",
    ]);
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM experiment_runs
      WHERE experiment_id = ? AND status = 'completed'
    `).get(experimentId)).toEqual({ count: 3 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM research_execution_receipts
      WHERE consumed_at IS NOT NULL AND consumed_by_run_id IS NOT NULL
    `).get()).toEqual({ count: 6 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM integrity_receipts
      WHERE algorithm = 'hmac-sha256'
        AND execution_environment_kind = 'local_bwrap'
        AND provider_model_json = 'null'
        AND exposure_receipt_ids_json = '[]'
    `).get()).toEqual({ count: 3 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM provider_exposure_receipts
    `).get()).toEqual({ count: 0 });
    const binding = database.prepare(`
      SELECT descriptor_version_hash, descriptor_source_sha256,
        descriptor_canonical_sha256, scenario_commitment,
        hidden_scenario_hash, opaque_scenario_id_hash
      FROM private_research_holdout_bindings
    `).get() as Record<string, string>;
    expect(Object.values(binding).every((value) =>
      /^[a-f0-9]{64}$/u.test(value))).toBe(true);
    expect(JSON.stringify(binding)).not.toContain(
      "operator-private-fixture-alpha",
    );
  }, 60_000);
});

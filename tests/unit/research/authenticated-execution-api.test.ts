import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import express, { type Request } from "express";
import {
  LocalSessionAuth,
  V2_CSRF_COOKIE,
  authenticateRequest,
  createLocalSessionRouter,
  parseCookieHeader,
} from "../../../server/auth";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../../server/db";
import {
  createResearchLabRouter,
  ExperimentRunner,
  IntegrityAuthority,
  parseResearchReadinessProbeDescriptor,
  ResearchExecutionBoundary,
  type ResearchReadinessProbeDescriptor,
} from "../../../server/research";

const servers: Server[] = [];
const databases: SqliteDatabase[] = [];
const boundaries: ResearchExecutionBoundary[] = [];
const runners: ExperimentRunner[] = [];
const directories: string[] = [];
const OPERATOR_TOKEN = "authenticated-research-operator-token-32-bytes";
const ACTOR_ID = "operator-authenticated-research";

afterEach(async () => {
  await Promise.all(runners.splice(0).map((runner) => runner.stop()));
  await Promise.all(boundaries.splice(0).map((boundary) => boundary.stop()));
  await Promise.all(servers.splice(0).map(
    (server) => new Promise<void>((resolve) => server.close(() => resolve())),
  ));
  databases.splice(0).reverse().forEach((database) => database.close());
  directories.splice(0).forEach((directory) =>
    rmSync(directory, { recursive: true, force: true }));
});

function descriptor(): ResearchReadinessProbeDescriptor {
  return parseResearchReadinessProbeDescriptor(
    JSON.parse(readFileSync(new URL(
        "../../../deployment/runtime-config/research-readiness-probe.v1.json",
        import.meta.url,
      ), "utf8")),
  );
}

async function authenticatedFixture(): Promise<{
  readonly database: SqliteDatabase;
  readonly boundary: ResearchExecutionBoundary;
  readonly runner: ExperimentRunner;
  readonly root: string;
  readonly cookie: string;
  readonly csrf: string;
}> {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-research-auth-api-"));
  directories.push(directory);
  const database = createDatabaseConnection({
    filename: join(directory, "research.sqlite"),
    verifyIntegrity: false,
  });
  databases.push(database);
  migrateDatabase(database);
  const boundary = new ResearchExecutionBoundary(
    descriptor(),
    "authenticated-research-integrity-key-material-32-bytes",
    join(directory, "execution"),
  );
  boundaries.push(boundary);
  await boundary.start();
  const integrityAuthority = new IntegrityAuthority(
    "authenticated-research-integrity-key-material-32-bytes",
  );
  const runner = new ExperimentRunner({
    database,
    boundary,
    integrityAuthority,
  });
  runners.push(runner);
  const auth = new LocalSessionAuth({
    operatorToken: OPERATOR_TOKEN,
    actorId: ACTOR_ID,
  });
  const requestActors = new WeakMap<Request, string>();
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createLocalSessionRouter({ auth, secureCookies: false }));
  app.use("/api/v2", (request, response, next) => {
    const result = authenticateRequest({
      auth,
      authorization: request.get("Authorization"),
      cookie: request.get("Cookie"),
      csrfHeader: request.get("x-ti-scale-csrf"),
      unsafeMethod: !["GET", "HEAD", "OPTIONS"].includes(request.method),
    });
    if (!result.authenticated) {
      response.status(result.failure.startsWith("csrf_") ? 403 : 401).json({
        error: { code: result.failure },
      });
      return;
    }
    requestActors.set(request, result.actorId);
    next();
  });
  app.use(createResearchLabRouter({
    database,
    resolveActor: (request) => {
      const id = requestActors.get(request);
      return id ? { id, type: "operator" } : undefined;
    },
    authorizePromotion: () => false,
    authorizeExecution: (_request, actor) => actor.id === ACTOR_ID,
    readRuntimeReadiness: () => boundary.readiness(),
    integrityAuthority,
    experimentRunner: runner,
  }));
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Authenticated Research test server has no address.");
  }
  const root = `http://127.0.0.1:${address.port}`;
  const login = await fetch(`${root}/api/v2/auth/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ operatorToken: OPERATOR_TOKEN }),
  });
  expect(login.status, await login.clone().text()).toBe(200);
  const issuedCookies = login.headers.getSetCookie().map(
    (value) => value.split(";", 1)[0]!,
  );
  const parsed = parseCookieHeader(issuedCookies.join("; "));
  const csrf = parsed[V2_CSRF_COOKIE];
  if (!csrf) throw new Error("Authenticated Research test has no CSRF cookie.");
  return {
    database,
    boundary,
    runner,
    root,
    cookie: issuedCookies.join("; "),
    csrf,
  };
}

async function mutate(
  fixture: Awaited<ReturnType<typeof authenticatedFixture>>,
  path: string,
  body: unknown,
  idempotencyKey: string,
  csrf = fixture.csrf,
): Promise<Response> {
  return fetch(`${fixture.root}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
      Cookie: fixture.cookie,
      "x-ti-scale-csrf": csrf,
    },
    body: JSON.stringify(body),
  });
}

async function createSetup(
  fixture: Awaited<ReturnType<typeof authenticatedFixture>>,
  catalogId:
    | "repeated_no_progress_action_reduction"
    | "specialist_routing_quality",
  suffix: string,
) {
  const created = await mutate(
    fixture,
    "/api/v2/research/campaigns",
    { catalogId, ownerAcknowledged: true },
    `authenticated-create-${suffix}`,
  );
  expect(created.status, await created.clone().text()).toBe(201);
  const creation = await created.json() as {
    readonly campaign: { readonly id: string; readonly updatedAt: string };
  };
  const snapshotResponse = await fetch(`${fixture.root}/api/v2/research`, {
    headers: { Cookie: fixture.cookie },
  });
  expect(snapshotResponse.status).toBe(200);
  const snapshot = await snapshotResponse.json() as {
    readonly catalog: readonly {
      readonly id: string;
      readonly setup: { readonly candidatePresetId: string };
    }[];
  };
  const candidatePresetId = snapshot.catalog.find(
    ({ id }) => id === catalogId,
  )!.setup.candidatePresetId;
  const setup = await mutate(
    fixture,
    `/api/v2/research/campaigns/${encodeURIComponent(creation.campaign.id)}/setup`,
    {
      expectedUpdatedAt: creation.campaign.updatedAt,
      candidatePresetId,
      ownerApproval: true,
    },
    `authenticated-setup-${suffix}`,
  );
  expect(setup.status, await setup.clone().text()).toBe(201);
  return await setup.json() as {
    readonly setup: {
      readonly experimentId: string;
      readonly developmentScenarioId: string;
    };
  };
}

describe("mounted authenticated Research execution API", () => {
  test("enforces session/CSRF, creates through the API, cancels exactly, and executes a locally judged run", async () => {
    const fixture = await authenticatedFixture();
    const anonymous = await fetch(
      `${fixture.root}/api/v2/research/campaigns`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "anonymous-research-create",
        },
        body: JSON.stringify({
          catalogId: "specialist_routing_quality",
          ownerAcknowledged: true,
        }),
      },
    );
    expect(anonymous.status).toBe(403);
    const csrfDenied = await mutate(
      fixture,
      "/api/v2/research/campaigns",
      {
        catalogId: "specialist_routing_quality",
        ownerAcknowledged: true,
      },
      "csrf-denied-research-create",
      "wrong-csrf-token",
    );
    expect(csrfDenied.status).toBe(403);
    expect(fixture.database.prepare(
      "SELECT COUNT(*) AS count FROM research_campaigns",
    ).get()).toEqual({ count: 0 });

    const cancelledSetup = await createSetup(
      fixture,
      "specialist_routing_quality",
      "cancel",
    );
    const queuedForCancellation = await mutate(
      fixture,
      `/api/v2/research/experiments/${encodeURIComponent(cancelledSetup.setup.experimentId)}/runs`,
      {
        scenarioId: cancelledSetup.setup.developmentScenarioId,
        seed: "authenticated-cancel-seed",
      },
      "authenticated-run-cancel",
    );
    expect(queuedForCancellation.status).toBe(202);
    const queuedPayload = await queuedForCancellation.json() as {
      readonly run: { readonly id: string; readonly status: string };
    };
    expect(queuedPayload.run.status).toBe("queued");
    const cancelled = await mutate(
      fixture,
      `/api/v2/research/experiments/${encodeURIComponent(cancelledSetup.setup.experimentId)}/runs/${encodeURIComponent(queuedPayload.run.id)}/cancel`,
      { reason: "The operator is validating exact queued-run cancellation." },
      "authenticated-cancel-exact",
    );
    expect(cancelled.status, await cancelled.clone().text()).toBe(200);
    expect(await cancelled.json()).toMatchObject({
      run: { id: queuedPayload.run.id, status: "cancelled" },
    });
    const cancelReplay = await mutate(
      fixture,
      `/api/v2/research/experiments/${encodeURIComponent(cancelledSetup.setup.experimentId)}/runs/${encodeURIComponent(queuedPayload.run.id)}/cancel`,
      { reason: "The operator is validating exact queued-run cancellation." },
      "authenticated-cancel-exact",
    );
    expect(cancelReplay.status).toBe(200);
    expect(await cancelReplay.json()).toMatchObject({
      run: { id: queuedPayload.run.id, status: "cancelled" },
    });
    const cancelConflict = await mutate(
      fixture,
      `/api/v2/research/experiments/${encodeURIComponent(cancelledSetup.setup.experimentId)}/runs/${encodeURIComponent(queuedPayload.run.id)}/cancel`,
      { reason: "This is a different cancellation body after terminal state." },
      "authenticated-cancel-exact",
    );
    expect(cancelConflict.status).toBe(409);
    expect(await cancelConflict.json()).toMatchObject({
      error: { code: "research_cancel_idempotency_conflict" },
    });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count
      FROM research_experiment_admissions
      WHERE experiment_run_id = ?
    `).get(queuedPayload.run.id)).toEqual({ count: 0 });

    const executableSetup = await createSetup(
      fixture,
      "repeated_no_progress_action_reduction",
      "execute",
    );
    const queued = await mutate(
      fixture,
      `/api/v2/research/experiments/${encodeURIComponent(executableSetup.setup.experimentId)}/runs`,
      {
        scenarioId: executableSetup.setup.developmentScenarioId,
        seed: "authenticated-execution-seed",
      },
      "authenticated-run-execute",
    );
    expect(queued.status, await queued.clone().text()).toBe(202);
    const queuedRun = await queued.json() as {
      readonly run: { readonly id: string };
    };
    fixture.runner.start();
    let terminal: {
      readonly run: { readonly status: string };
    } = { run: { status: "queued" } };
    for (let index = 0; index < 200; index += 1) {
      const response = await fetch(
        `${fixture.root}/api/v2/research/experiments/${encodeURIComponent(executableSetup.setup.experimentId)}/runs/${encodeURIComponent(queuedRun.run.id)}`,
        { headers: { Cookie: fixture.cookie } },
      );
      expect(response.status, await response.clone().text()).toBe(200);
      terminal = await response.json() as typeof terminal;
      if (!["queued", "running"].includes(terminal.run.status)) break;
      await Bun.sleep(25);
    }
    expect(terminal.run.status).toBe("completed");
    const terminalCancel = await mutate(
      fixture,
      `/api/v2/research/experiments/${encodeURIComponent(executableSetup.setup.experimentId)}/runs/${encodeURIComponent(queuedRun.run.id)}/cancel`,
      { reason: "Record an idempotent terminal-first cancellation request." },
      "authenticated-terminal-first-cancel",
    );
    expect(terminalCancel.status).toBe(200);
    expect(await terminalCancel.json()).toMatchObject({
      run: { id: queuedRun.run.id, status: "completed" },
    });
    const terminalCancelConflict = await mutate(
      fixture,
      `/api/v2/research/experiments/${encodeURIComponent(executableSetup.setup.experimentId)}/runs/${encodeURIComponent(queuedRun.run.id)}/cancel`,
      { reason: "A different body must conflict even though the run is terminal." },
      "authenticated-terminal-first-cancel",
    );
    expect(terminalCancelConflict.status).toBe(409);
    expect(await terminalCancelConflict.json()).toMatchObject({
      error: { code: "research_cancel_idempotency_conflict" },
    });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count
      FROM experiment_metrics
      WHERE experiment_run_id = ? AND authoritative = 1
    `).get(queuedRun.run.id)).toEqual({ count: 2 });
    expect(fixture.database.prepare(`
      SELECT execution_environment_kind, algorithm, evaluation_stage,
        evaluation_action
      FROM integrity_receipts
      WHERE evaluation_attempt_id = ?
    `).get(queuedRun.run.id)).toEqual({
      execution_environment_kind: "local_bwrap",
      algorithm: "hmac-sha256",
      evaluation_stage: "development",
      evaluation_action: "development_pass",
    });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM benchmark_scenarios
      WHERE split = 'hidden_holdout'
    `).get()).toEqual({ count: 0 });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM provider_exposure_receipts
      WHERE experiment_id IS NOT NULL
    `).get()).toEqual({ count: 0 });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM strategy_deployments
    `).get()).toEqual({ count: 0 });
  }, 30_000);
});

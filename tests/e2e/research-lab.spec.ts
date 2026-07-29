import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import express from "express";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../server/db";
import {
  createResearchLabRouter,
  ExperimentRunner,
  IntegrityAuthority,
  parseResearchReadinessProbeDescriptor,
  ResearchExecutionBoundary,
  type ResearchExperimentRunRecord,
  type ResearchReadinessProbeDescriptor,
} from "../../server/research";
import {
  expect,
  test,
  type Locator,
  type Page,
  type Response,
  type Route,
} from "./support/playwright";
import { E2E_RUN_ID } from "./support/environment";
import {
  advanceResearchCampaignVersion,
  holdResearchLabWriteLock,
  readResearchCampaignFixtureState,
} from "./support/researchLabFixture";
import {
  advanceResearchPromotionHumanDecision,
  completeResearchPromotionLifecycleFixture,
  readResearchPromotionCandidateVersion,
  readResearchPromotionFixtureState,
  recordResearchPromotionEvaluatorPass,
  seedResearchPromotionActionMatrixFixture,
  seedResearchPromotionLifecycleFixture,
  seedResearchPromotionReliabilityFixture,
  type ResearchPromotionActionMatrixFixture,
  type ResearchPromotionLifecycleFixture,
  type ResearchPromotionReliabilityFixture,
} from "./support/researchPromotionLifecycleFixture";

const TEST_IDS = {
  lifecycle: "e2e.research-lab.bounded-campaign-lifecycle",
  retryable: "e2e.research-lab.retryable-mutations",
  conflict: "e2e.research-lab.optimistic-conflict",
  promotion: "e2e.research-lab.complete-promotion-lifecycle",
  promotionActions: "e2e.research-lab.promotion-action-matrix",
  promotionReliability: "e2e.research-lab.promotion-reliability",
  promotionResponseLoss: "e2e.research-lab.promotion-response-loss",
  experimentControls: "e2e.research-lab.bounded-experiment-controls",
  initialReadPointer: "e2e.research-lab.initial-read-retry.pointer",
  initialReadKeyboard: "e2e.research-lab.initial-read-retry.keyboard",
  setupConflict: "e2e.research-lab.setup-optimistic-conflict",
  completedWorker: "e2e.research-lab.authoritative-worker-completion",
  experimentRetry: "e2e.research-lab.experiment-mutation-retry",
  experimentResponseLoss:
    "e2e.research-lab.experiment-response-loss-reconciliation",
} as const;

const PROMOTION_ACTION_LABELS = {
  approve_human_review: "Approve for isolated shadow",
  reject_human_review: "Reject after human review",
  start_shadow: "Start isolated shadow",
  approve_canary: "Approve bounded canary",
  start_canary: "Start bounded canary",
  verify: "Verify strategy",
  reject: "Reject candidate",
  mark_stale: "Mark strategy stale",
  supersede: "Supersede strategy",
  rollback: "Roll back by forward activation",
} as const;

const PROMOTION_ACTION_MATERIAL_STATE =
  "A candidate is at a lifecycle state with represented human actions";
const PROMOTION_RETAINED_DECISION_MATERIAL_STATE =
  "A retryable or response-uncertain promotion decision is retained in the actor-scoped tab session";

const CAMPAIGNS = [
  {
    id: "repeated_no_progress_action_reduction",
    title: "Repeated and no-progress action reduction",
    expectedPath: "/loopControl/maxIdenticalFingerprints",
    strategyOption: "Repeated and no-progress action reduction paths",
    createOption: "Create repeated/no-progress reduction draft",
  },
  {
    id: "specialist_routing_quality",
    title: "Specialist routing quality",
    expectedPath: "/specialistRouting/minimumCapabilityScore",
    strategyOption: "Specialist routing quality paths",
    createOption: "Create specialist-routing quality draft",
  },
  {
    id: "memory_retrieval_precision",
    title: "Memory retrieval precision",
    expectedPath: "/memoryRetrieval/maxContextItems",
    strategyOption: "Memory retrieval precision paths",
    createOption: "Create memory-retrieval precision draft",
  },
] as const;

async function acquireResearchMutationLock(): Promise<() => void> {
  const lockPath = resolve(
    "/tmp/ti-scale-e2e-data",
    `research-lab-${E2E_RUN_ID.replace(/[^A-Za-z0-9._-]+/gu, "-")}.lock`,
  );
  const deadline = Date.now() + 180_000;
  while (true) {
    try {
      mkdirSync(lockPath);
      return () => rmSync(lockPath, { recursive: true, force: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (Date.now() >= deadline) {
        throw new Error(`Timed out waiting for the isolated Research Lab mutation lock: ${lockPath}`);
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
  }
}

let releaseResearchLabIsolation: (() => void) | undefined;

test.beforeEach(async ({}, testInfo) => {
  // Every Research page still uses the shared shell for authentication,
  // notifications, and SSE even when its Research API is test-local. A test
  // that deliberately holds the shared SQLite writer lock would otherwise
  // synchronously stall those unrelated routes in another browser project.
  testInfo.setTimeout(Math.max(testInfo.timeout, 900_000));
  releaseResearchLabIsolation = await acquireResearchMutationLock();
});

test.afterEach(async ({ page, browserAudit }) => {
  try {
    // Keep the cross-process boundary until the browser has produced an exact
    // close receipt, so auth/notification/SSE teardown cannot overlap the next
    // intentional database-pressure fixture.
    await browserAudit.closePageBeforeDependencyShutdown(page);
  } finally {
    releaseResearchLabIsolation?.();
    releaseResearchLabIsolation = undefined;
  }
});

function campaignCard(page: import("./support/playwright").Page, title: string): Locator {
  return page.locator(".os-research-campaigns > .os-card").filter({
    has: page.getByRole("heading", { name: title, exact: true }),
  });
}

interface ExecutableResearchBrowserFixture {
  readonly database: SqliteDatabase;
  readonly databasePath: string;
  readonly root: string;
  readonly runner: ExperimentRunner;
}

function researchReadinessDescriptor(): ResearchReadinessProbeDescriptor {
  return parseResearchReadinessProbeDescriptor(JSON.parse(readFileSync(
    new URL(
      "../../deployment/runtime-config/research-readiness-probe.v1.json",
      import.meta.url,
    ),
    "utf8",
  )));
}

async function withExecutableResearchBrowserFixture<T>(
  page: Page,
  use: (fixture: ExecutableResearchBrowserFixture) => Promise<T>,
): Promise<T> {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-research-browser-"));
  const databasePath = join(directory, "research.sqlite");
  const database = createDatabaseConnection({
    filename: databasePath,
    busyTimeoutMs: 100,
    verifyIntegrity: false,
  });
  migrateDatabase(database);
  const integrityKey = "browser-research-integrity-key-material-32-bytes";
  const boundary = new ResearchExecutionBoundary(
    researchReadinessDescriptor(),
    integrityKey,
    join(directory, "execution"),
  );
  await boundary.start();
  const runner = new ExperimentRunner({
    database,
    boundary,
    integrityAuthority: new IntegrityAuthority(integrityKey),
  });
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createResearchLabRouter({
    database,
    resolveActor: () => ({ id: "e2e-local-operator", type: "operator" }),
    authorizePromotion: () => false,
    authorizeExecution: () => true,
    readRuntimeReadiness: () => boundary.readiness(),
    integrityAuthority: new IntegrityAuthority(integrityKey),
    experimentRunner: runner,
  }));
  const server = createServer(app);
  await new Promise<void>((resolveListen) =>
    server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Executable Research browser fixture has no address.");
  }
  const root = `http://127.0.0.1:${address.port}`;
  await page.route("**/api/v2/research**", async (route) => {
    const request = route.request();
    const requested = new URL(request.url());
    const headers = { ...request.headers() };
    delete headers.host;
    delete headers.origin;
    delete headers.referer;
    delete headers.cookie;
    const result = await fetch(`${root}${requested.pathname}${requested.search}`, {
      method: request.method(),
      headers,
      ...(request.postDataBuffer()
        ? { body: request.postDataBuffer() }
        : {}),
    });
    const responseHeaders = Object.fromEntries(result.headers.entries());
    await route.fulfill({
      status: result.status,
      headers: responseHeaders,
      body: Buffer.from(await result.arrayBuffer()),
    });
  });
  try {
    return await use({ database, databasePath, root, runner });
  } finally {
    await page.unroute("**/api/v2/research**");
    await runner.stop();
    await boundary.stop();
    await new Promise<void>((resolveClose, rejectClose) =>
      server.close((error) => error ? rejectClose(error) : resolveClose()));
    database.close();
    rmSync(directory, { recursive: true, force: true });
  }
}

async function expectCreateResponse(response: Response, catalogId: string): Promise<{
  readonly id: string;
  readonly updatedAt: string;
}> {
  expect(response.status(), await response.text()).toBe(201);
  expect(response.request().method()).toBe("POST");
  expect(response.request().headers()["idempotency-key"]).toMatch(/^research-create-[0-9a-f-]+$/u);
  expect(response.request().postDataJSON()).toEqual({ catalogId, ownerAcknowledged: true });
  const payload = await response.json() as {
    schemaVersion: string;
    campaign: { id: string; catalogId: string; status: string; owner: string; updatedAt: string };
    nextUrl: string;
  };
  expect(payload).toMatchObject({
    schemaVersion: "2.4",
    campaign: {
      catalogId,
      status: "draft",
      owner: "e2e-local-operator",
    },
  });
  expect(payload.nextUrl).toContain(`/learning?view=research&campaign=${encodeURIComponent(payload.campaign.id)}`);
  return { id: payload.campaign.id, updatedAt: payload.campaign.updatedAt };
}

function advanceExecutableCampaignVersion(
  database: SqliteDatabase,
  campaignId: string,
): string {
  const row = database.prepare(`
    SELECT updated_at FROM research_campaigns WHERE id = ?
  `).get(campaignId) as { readonly updated_at: string } | undefined;
  if (!row) throw new Error(`Research campaign ${campaignId} does not exist`);
  const current = Date.parse(row.updated_at);
  if (!Number.isFinite(current)) {
    throw new Error(`Research campaign ${campaignId} has an invalid timestamp`);
  }
  const updatedAt = new Date(
    Math.max(current + 1_000, Date.now() + 1_000),
  ).toISOString();
  const result = database.prepare(`
    UPDATE research_campaigns
    SET updated_at = ?
    WHERE id = ? AND updated_at = ?
  `).run(updatedAt, campaignId, row.updated_at);
  if (result.changes !== 1) {
    throw new Error(
      `Research campaign ${campaignId} changed while advancing its fixture version`,
    );
  }
  return updatedAt;
}

function readExecutableSetupState(
  database: SqliteDatabase,
  campaignId: string,
): {
  readonly charters: number;
  readonly experiments: number;
  readonly patches: number;
  readonly setupApprovals: number;
  readonly deployments: number;
  readonly providerExposures: number;
} {
  const row = database.prepare(`
    SELECT
      (SELECT COUNT(*) FROM research_charters
        WHERE campaign_id = ?) AS charters,
      (SELECT COUNT(*) FROM experiments
        WHERE campaign_id = ?) AS experiments,
      (SELECT COUNT(*) FROM strategy_patches patch
        JOIN strategy_versions strategy
          ON strategy.id = patch.strategy_version_id
        WHERE strategy.campaign_id = ?) AS patches,
      (SELECT COUNT(*) FROM audit_records
        WHERE resource_id = ?
          AND action = 'research_campaign.setup_approved') AS setup_approvals,
      (SELECT COUNT(*) FROM strategy_deployments deployment
        JOIN strategy_versions strategy
          ON strategy.id = deployment.strategy_version_id
        WHERE strategy.campaign_id = ?) AS deployments,
      (SELECT COUNT(*) FROM provider_exposure_receipts receipt
        JOIN experiments experiment ON experiment.id = receipt.experiment_id
        WHERE experiment.campaign_id = ?) AS provider_exposures
  `).get(
    campaignId,
    campaignId,
    campaignId,
    campaignId,
    campaignId,
    campaignId,
  ) as {
    readonly charters: number;
    readonly experiments: number;
    readonly patches: number;
    readonly setup_approvals: number;
    readonly deployments: number;
    readonly provider_exposures: number;
  };
  return {
    charters: row.charters,
    experiments: row.experiments,
    patches: row.patches,
    setupApprovals: row.setup_approvals,
    deployments: row.deployments,
    providerExposures: row.provider_exposures,
  };
}

async function queueExecutableExperiment(
  page: Page,
  campaignIndex: number,
): Promise<{
  readonly campaignId: string;
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly candidateStrategyId: string;
  readonly row: Locator;
}> {
  const catalog = CAMPAIGNS[campaignIndex];
  if (!catalog) throw new Error(`Unknown Research campaign fixture ${campaignIndex}`);
  const card = campaignCard(page, catalog.title);
  const createResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/v2/research/campaigns"
    && response.request().method() === "POST"
    && response.status() === 201);
  await card.getByRole("button", {
    name: "Create bounded draft",
    exact: true,
  }).click();
  const campaign = await expectCreateResponse(
    await createResponse,
    catalog.id,
  );
  const control = card.locator(".os-research-control");
  await control.getByRole("checkbox", {
    name: /I approve this exact charter, patch, fixture, and budget/u,
  }).check();
  const setupResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname
      === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/setup`
    && response.request().method() === "POST"
    && response.status() === 201);
  await control.getByRole("button", {
    name: "Approve and queue candidate",
    exact: true,
  }).click();
  const setup = await (await setupResponse).json() as {
    readonly setup: {
      readonly experimentId: string;
      readonly developmentScenarioId: string;
      readonly candidateStrategyId: string;
    };
  };
  return {
    campaignId: campaign.id,
    experimentId: setup.setup.experimentId,
    scenarioId: setup.setup.developmentScenarioId,
    candidateStrategyId: setup.setup.candidateStrategyId,
    row: page.getByRole("row").filter({
      hasText: setup.setup.candidateStrategyId,
    }),
  };
}

async function forwardResearchMutationAsLostResponse(input: {
  readonly route: Route;
  readonly root: string;
  readonly expectedStatus: 200 | 202;
}): Promise<{
  readonly canonical: {
    readonly schemaVersion: string;
    readonly run: ResearchExperimentRunRecord;
  };
  readonly idempotencyKey: string;
  readonly serializedBody: string;
}> {
  const request = input.route.request();
  const requested = new URL(request.url());
  const headers = { ...request.headers() };
  delete headers.host;
  delete headers.origin;
  delete headers.referer;
  delete headers.cookie;
  const serializedBody = request.postData() ?? "";
  const upstream = await fetch(
    `${input.root}${requested.pathname}${requested.search}`,
    {
      method: request.method(),
      headers,
      ...(request.postDataBuffer()
        ? { body: request.postDataBuffer() }
        : {}),
    },
  );
  const upstreamBody = await upstream.text();
  expect(upstream.status, upstreamBody).toBe(input.expectedStatus);
  const canonical = JSON.parse(upstreamBody) as {
    readonly schemaVersion: string;
    readonly run: ResearchExperimentRunRecord;
  };
  expect(canonical).toMatchObject({
    schemaVersion: "2.4",
    run: { id: expect.any(String) },
  });
  const responseHeaders = Object.fromEntries(upstream.headers.entries());
  delete responseHeaders["content-encoding"];
  delete responseHeaders["content-length"];
  delete responseHeaders["transfer-encoding"];
  await input.route.fulfill({
    status: input.expectedStatus,
    headers: {
      ...responseHeaders,
      "content-type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({
      schemaVersion: "2.4",
      run: null,
    }),
  });
  return {
    canonical,
    idempotencyKey: request.headers()["idempotency-key"] ?? "",
    serializedBody,
  };
}

for (const modality of ["pointer", "keyboard"] as const) {
  const testId = modality === "pointer"
    ? TEST_IDS.initialReadPointer
    : TEST_IDS.initialReadKeyboard;
  test(`${testId} replaces the initial read error with a bounded canonical retry`, async ({
    page,
    browserAudit,
    interactionActivation,
  }) => {
    let requestCount = 0;
    let releaseRetry!: () => void;
    const retryGate = new Promise<void>((resolveRetry) => {
      releaseRetry = resolveRetry;
    });
    let markRetryStarted!: () => void;
    const retryStarted = new Promise<void>((resolveStarted) => {
      markRetryStarted = resolveStarted;
    });
    await page.route("**/api/v2/research", async (route) => {
      const request = route.request();
      const requested = new URL(request.url());
      if (
        request.method() !== "GET"
        || requested.pathname !== "/api/v2/research"
      ) {
        await route.continue();
        return;
      }
      requestCount += 1;
      if (requestCount === 1) {
        await route.fulfill({
          status: 503,
          headers: {
            "content-type": "application/json",
            "x-request-id": `research-initial-${modality}`,
          },
          body: JSON.stringify({
            error: {
              code: "research_snapshot_unavailable",
              message: "The canonical Research Lab snapshot is unavailable.",
              humanMessage:
                "The canonical Research Lab snapshot is temporarily unavailable.",
              retryable: true,
              category: "dependency",
              remediation: "Try the canonical Research Lab read again.",
              traceId: `research-initial-${modality}`,
              timestamp: "2026-07-27T00:00:00.000Z",
            },
          }),
        });
        return;
      }
      if (requestCount === 2) {
        markRetryStarted();
        await retryGate;
      }
      await route.continue();
    });
    browserAudit.expectHttpResponse(page, {
      id: `research-lab.snapshot.initial-unavailable.${modality}`,
      transport: "browser",
      method: "GET",
      pathname: "/api/v2/research",
      query: {},
      status: 503,
      occurrences: 1,
      reason:
        "Prove the no-cache Research Lab read exposes one precise retry before a fresh canonical read.",
    });
    try {
      await page.goto("/learning?view=research", {
        waitUntil: "domcontentloaded",
      });
      const alert = page.getByRole("alert").filter({
        hasText: "Research Lab state is unavailable",
      });
      await expect(alert).toContainText(
        "The canonical Research Lab snapshot is temporarily unavailable.",
      );
      const retry = alert.getByRole("button", {
        name: "Try again",
        exact: true,
      });
      const activate = () => modality === "pointer"
        ? retry.click()
        : retry.press("Enter");
      if (modality === "keyboard") {
        await retry.focus();
        await expect(retry).toBeFocused();
      }
      await interactionActivation.activate({
        manifestEntryId: "research.initial-read-retry",
        controlId: "research-initial-read-retry",
        option: "Retry the canonical Research Lab snapshot",
        materialState:
          "Fixture required: the initial canonical Research Lab snapshot fails without cached data",
        modality,
        testId,
      }, activate);
      await retryStarted;
      await expect(page.getByText(
        "Loading bounded Research Lab state",
        { exact: true },
      )).toBeVisible();
      await expect(page.getByRole("button", {
        name: "Try again",
        exact: true,
      })).toHaveCount(0);
      releaseRetry();
      await expect(page.getByRole("heading", {
        name: "Readiness gate",
        exact: true,
      })).toBeVisible();
      expect(requestCount).toBe(2);
    } finally {
      releaseRetry();
      await page.unroute("**/api/v2/research");
    }
  });
}

test(`${TEST_IDS.setupConflict} invalidates stale setup approval before a newly reviewed queue`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  await withExecutableResearchBrowserFixture(page, async ({ database }) => {
    await page.goto("/learning?view=research", {
      waitUntil: "domcontentloaded",
    });
    await page.getByRole("checkbox", {
      name: /I own this campaign and its promotion decisions/u,
    }).check();
    const catalog = CAMPAIGNS[0];
    const card = campaignCard(page, catalog.title);
    const createResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research/campaigns"
      && response.request().method() === "POST"
      && response.status() === 201);
    await card.getByRole("button", {
      name: "Create bounded draft",
      exact: true,
    }).click();
    const campaign = await expectCreateResponse(
      await createResponse,
      catalog.id,
    );
    const controls = card.locator(".os-research-control");
    const approval = controls.getByRole("checkbox", {
      name: /I approve this exact charter, patch, fixture, and budget/u,
    });
    const queue = controls.getByRole("button", {
      name: "Approve and queue candidate",
      exact: true,
    });
    const setupPath =
      `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/setup`;
    browserAudit.expectHttpResponse(page, {
      id: "research-lab.setup.version-conflict",
      transport: "browser",
      method: "POST",
      pathname: setupPath,
      query: {},
      status: 409,
      occurrences: 2,
      reason:
        "Prove pointer and keyboard refresh both follow a genuine stale exact-setup denial without replaying it.",
    });

    let representedUpdatedAt = campaign.updatedAt;
    const staleKeys: string[] = [];
    for (const modality of ["pointer", "keyboard"] as const) {
      await approval.check();
      await expect(approval).toBeChecked();
      const canonicalUpdatedAt = advanceExecutableCampaignVersion(
        database,
        campaign.id,
      );
      const conflictPromise = page.waitForResponse((response) =>
        new URL(response.url()).pathname === setupPath
        && response.request().method() === "POST"
        && response.status() === 409);
      await (modality === "pointer" ? queue.click() : queue.press("Enter"));
      const conflict = await conflictPromise;
      const key = conflict.request().headers()["idempotency-key"];
      staleKeys.push(key);
      expect(key).toMatch(/^research-setup-[0-9a-f-]+$/u);
      expect(conflict.request().postDataJSON()).toMatchObject({
        expectedUpdatedAt: representedUpdatedAt,
        ownerApproval: true,
      });
      expect(await conflict.json()).toMatchObject({
        error: {
          code: "research_campaign_version_conflict",
          retryable: false,
          humanMessage: "The campaign changed after this setup was reviewed.",
          remediation:
            "Refresh the Research Lab and review the exact current patch and benchmark bindings.",
        },
      });
      const refresh = controls.getByRole("button", {
        name: "Refresh exact setup bindings",
        exact: true,
      });
      await expect(refresh).toBeFocused();
      await expect(queue).toBeDisabled();
      const canonicalRead = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/api/v2/research"
        && response.request().method() === "GET"
        && response.status() === 200);
      await interactionActivation.activate({
        manifestEntryId: "research.setup-refresh",
        controlId: "research-setup-refresh",
        option:
          "Refresh exact setup after optimistic campaign-version conflict",
        materialState:
          "Fixture required: the reviewed setup timestamp is stale after a concurrent canonical campaign update",
        modality,
        testId: TEST_IDS.setupConflict,
      }, () => modality === "pointer"
        ? refresh.click()
        : refresh.press("Enter"));
      const snapshot = await (await canonicalRead).json() as {
        readonly campaigns: readonly {
          readonly id: string;
          readonly updatedAt: string;
        }[];
      };
      expect(snapshot.campaigns.find(({ id }) =>
        id === campaign.id)?.updatedAt).toBe(canonicalUpdatedAt);
      representedUpdatedAt = canonicalUpdatedAt;
      await expect(approval).not.toBeChecked();
      await expect(approval).toBeFocused();
      await expect(queue).toBeDisabled();
      expect(readExecutableSetupState(database, campaign.id)).toEqual({
        charters: 0,
        experiments: 0,
        patches: 0,
        setupApprovals: 0,
        deployments: 0,
        providerExposures: 0,
      });
    }
    expect(staleKeys[1]).not.toBe(staleKeys[0]);

    await approval.check();
    const finalSetupResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === setupPath
      && response.request().method() === "POST"
      && response.status() === 201);
    await queue.click();
    const finalSetup = await finalSetupResponse;
    expect(finalSetup.request().headers()["idempotency-key"])
      .not.toBe(staleKeys[0]);
    expect(finalSetup.request().headers()["idempotency-key"])
      .not.toBe(staleKeys[1]);
    expect(finalSetup.request().postDataJSON()).toMatchObject({
      expectedUpdatedAt: representedUpdatedAt,
      ownerApproval: true,
    });
    expect(readExecutableSetupState(database, campaign.id)).toEqual({
      charters: 1,
      experiments: 1,
      patches: 1,
      setupApprovals: 1,
      deployments: 0,
      providerExposures: 0,
    });
  });
});

test(`${TEST_IDS.lifecycle} exercises every bounded draft and stop control against canonical state`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(240_000);
  const createdCampaignIds: string[] = [];
    const initialRead = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research"
      && response.request().method() === "GET");
    await page.goto("/learning?view=research", { waitUntil: "domcontentloaded" });
    const initialResponse = await initialRead;
    expect(initialResponse.status()).toBe(200);
    const initialSnapshot = await initialResponse.json() as {
      readonly experiments: readonly unknown[];
    };

    await expect(page.getByRole("heading", { name: "Learning Lab", exact: true })).toBeVisible();
    await expect(page.getByText("Research execution is safely blocked", { exact: true })).toBeVisible();
    if (initialSnapshot.experiments.length === 0) {
      await expect(page.getByText("No experiments have run", { exact: true })).toBeVisible();
    } else {
      await expect(page.getByRole("table")).toBeVisible();
    }

    const ownership = page.getByRole("checkbox", {
      name: /I own this campaign and its promotion decisions/u,
    });
    await expect(ownership).not.toBeChecked();
    await expect(page.getByRole("button", { name: "Create bounded draft", exact: true })).toHaveCount(3);
    for (const button of await page.getByRole("button", { name: "Create bounded draft", exact: true }).all()) {
      await expect(button).toBeDisabled();
    }
    const ownershipReceipt = {
      manifestEntryId: "research.owner-acknowledgement",
      controlId: "research-owner-acknowledgement",
      option: "Confirm human ownership before enabling any draft creation",
      materialState: "The bounded Research Lab catalog is loaded",
      testId: TEST_IDS.lifecycle,
    } as const;
    await interactionActivation.activate({
      ...ownershipReceipt,
      modality: "pointer",
    }, () => ownership.click());
    await expect(ownership).toBeChecked();
    await ownership.click();
    await expect(ownership).not.toBeChecked();
    await interactionActivation.activate({
      ...ownershipReceipt,
      modality: "keyboard",
    }, async () => {
      await ownership.focus();
      await expect(ownership).toBeFocused();
      await ownership.press("Space");
    });
    await expect(ownership).toBeChecked();

    for (const [campaignIndex, campaign] of CAMPAIGNS.entries()) {
      for (const modality of ["pointer", "keyboard"] as const) {
        const card = campaignCard(page, campaign.title);
        await expect(card).toHaveCount(1);
        const strategyDisclosure = card.locator("summary").filter({
          hasText: "Allowed strategy paths",
        });
        await interactionActivation.activate({
          manifestEntryId: "research.allowed-strategy-paths",
          controlId: "research-allowed-strategy-paths",
          option: campaign.strategyOption,
          materialState: "All three registered safety and reliability tracks are loaded",
          modality,
          testId: TEST_IDS.lifecycle,
        }, () => modality === "pointer"
          ? strategyDisclosure.click()
          : strategyDisclosure.press("Enter"));
        await expect(card).toContainText(campaign.expectedPath);
        await strategyDisclosure.click();

        const createResponsePromise = page.waitForResponse((response) =>
          new URL(response.url()).pathname === "/api/v2/research/campaigns"
          && response.request().method() === "POST");
        const createButton = card.getByRole("button", {
          name: "Create bounded draft",
          exact: true,
        });
        await interactionActivation.activate({
          manifestEntryId: "research.create-draft",
          controlId: "research-create-draft",
          option: campaign.createOption,
          materialState: "Human ownership is acknowledged and no active campaign exists for the represented track",
          modality,
          testId: TEST_IDS.lifecycle,
        }, () => modality === "pointer"
          ? createButton.click()
          : createButton.press("Enter"));
        const { id: campaignId } = await expectCreateResponse(
          await createResponsePromise,
          campaign.id,
        );
        createdCampaignIds.push(campaignId);

        await expect(page.locator("p.os-success-note")).toContainText("Draft campaign created");
        await expect(card.getByText("draft", { exact: true })).toBeVisible();
        const controls = card.locator(".os-research-control");
        await expect(controls).toHaveCount(1);
        const stopDisclosure = controls.locator("summary").filter({
          hasText: "Stop campaign",
        });
        const disclosureAction = () => modality === "pointer"
          ? stopDisclosure.click()
          : stopDisclosure.press("Enter");
        if (campaignIndex === 0) {
          await interactionActivation.activate({
            manifestEntryId: "research.campaign-controls",
            controlId: "research-campaign-controls",
            option: "Open bounded campaign stop controls",
            materialState: "A human-owned nonterminal research campaign exists for the represented track",
            modality,
            testId: TEST_IDS.lifecycle,
          }, disclosureAction);
        } else {
          await disclosureAction();
        }
        const reason = controls.getByRole("textbox", {
          name: "Reason for stopping",
          exact: true,
        });
        const stop = controls.getByRole("button", {
          name: "Stop campaign",
          exact: true,
        });
        await expect(stop).toBeDisabled();
        const stopReason =
          `Browser verification completed for ${campaign.title} via ${modality}.`;
        const reasonAction = async () => {
          if (modality === "pointer") {
            await reason.click();
            await reason.fill(stopReason);
          } else {
            await reason.focus();
            await reason.pressSequentially(stopReason);
          }
        };
        if (campaignIndex === 0) {
          await interactionActivation.activate({
            manifestEntryId: "research.stop-reason",
            controlId: "research-stop-reason",
            option: "Record an attributable stop reason of at least three characters",
            materialState: "Stop campaign controls are expanded for a human-owned nonterminal draft",
            modality,
            testId: TEST_IDS.lifecycle,
          }, reasonAction);
        } else {
          await reasonAction();
        }
        await expect(stop).toBeEnabled();

        const stopResponsePromise = page.waitForResponse((response) =>
          new URL(response.url()).pathname
            === `/api/v2/research/campaigns/${encodeURIComponent(campaignId)}/stop`
          && response.request().method() === "POST");
        const stopAction = () => modality === "pointer"
          ? stop.click()
          : stop.press("Enter");
        if (campaignIndex === 0) {
          await interactionActivation.activate({
            manifestEntryId: "research.stop-campaign",
            controlId: "research-stop-campaign",
            option: "Stop the represented campaign while preserving its audit history",
            materialState: "A valid stop reason is represented against the current campaign version",
            modality,
            testId: TEST_IDS.lifecycle,
          }, stopAction);
        } else {
          await stopAction();
        }
        const stopResponse = await stopResponsePromise;
        expect(stopResponse.status(), await stopResponse.text()).toBe(200);
        expect(stopResponse.request().headers()["idempotency-key"]).toMatch(
          /^research-stop-[0-9a-f-]+$/u,
        );
        const stopRequest = stopResponse.request().postDataJSON() as {
          expectedUpdatedAt?: string;
          reason?: string;
        };
        expect(stopRequest.expectedUpdatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/u);
        expect(stopRequest.reason).toBe(stopReason);
        const stopped = await stopResponse.json() as {
          campaign: { id: string; status: string };
        };
        expect(stopped.campaign).toEqual(expect.objectContaining({
          id: campaignId,
          status: "stopped",
        }));

        await expect(card.getByRole("button", {
          name: "Create bounded draft",
          exact: true,
        })).toBeVisible();
        await expect(card).toContainText("Prior campaigns");
      }
    }

    const finalRead = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research"
      && response.request().method() === "GET");
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.reload({ waitUntil: "domcontentloaded" }),
    );
    const finalResponse = await finalRead;
    expect(finalResponse.status()).toBe(200);
    const snapshot = await finalResponse.json() as {
      campaigns: { id: string; catalogId: string; status: string }[];
      experiments: { campaignId: string }[];
    };
    for (const campaign of CAMPAIGNS) {
      expect(snapshot.campaigns).toContainEqual(expect.objectContaining({
        catalogId: campaign.id,
        status: "stopped",
      }));
    }
  expect(
    snapshot.experiments.filter(({ campaignId }) =>
      createdCampaignIds.includes(campaignId)),
  ).toEqual([]);
});

test(`${TEST_IDS.experimentControls} reviews, queues, starts, and cancels exact synthetic experiments`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(180_000);
  await withExecutableResearchBrowserFixture(page, async (fixture) => {
    await page.goto("/learning?view=research", { waitUntil: "domcontentloaded" });
    await expect(page.getByText(
      "Research execution is safely blocked",
      { exact: true },
    )).toBeVisible();
    await page.getByRole("checkbox", {
      name: /I own this campaign and its promotion decisions/u,
    }).check();

    for (const [index, campaign] of CAMPAIGNS.slice(0, 2).entries()) {
      const modality = index === 0 ? "pointer" : "keyboard";
      const card = campaignCard(page, campaign.title);
      const createResponsePromise = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/api/v2/research/campaigns"
        && response.request().method() === "POST"
        && response.status() === 201);
      await card.getByRole("button", {
        name: "Create bounded draft",
        exact: true,
      }).click();
      const campaignRecord = await expectCreateResponse(
        await createResponsePromise,
        campaign.id,
      );
      const control = card.locator(".os-research-control");
      const review = control.locator("summary").filter({
        hasText: "Review exact bounded experiment",
      });
      await expect(review).toHaveCount(1);
      await interactionActivation.activate({
        manifestEntryId: "research.setup-disclosures",
        controlId: "research-setup-disclosures",
        option: "Open or close the exact bounded experiment review",
        materialState: "Fixture required: a human-owned draft is bound to an attested synthetic-only Research execution boundary",
        modality: "pointer",
        testId: TEST_IDS.experimentControls,
      }, () => review.click());
      await expect(control.getByText(
        "Target: synthetic fixture only",
        { exact: true },
      )).toBeHidden();
      await interactionActivation.activate({
        manifestEntryId: "research.setup-disclosures",
        controlId: "research-setup-disclosures",
        option: "Open or close the exact bounded experiment review",
        materialState: "Fixture required: a human-owned draft is bound to an attested synthetic-only Research execution boundary",
        modality: "keyboard",
        testId: TEST_IDS.experimentControls,
      }, () => review.press("Enter"));
      await expect(control.getByText(
        "Target: synthetic fixture only",
        { exact: true },
      )).toBeVisible();

      for (const disclosure of [
        {
          name: "Exact one-operation strategy patch",
          option: "Inspect the exact one-operation StrategyBundle patch",
          expected: campaign.expectedPath,
        },
        {
          name: "Immutable execution hashes",
          option: "Inspect immutable strategy, evaluator, tool, and execution-boundary hashes",
          expected: "executionEnvironmentIdentityHash",
        },
      ] as const) {
        const summary = control.locator("summary").filter({
          hasText: disclosure.name,
        });
        await interactionActivation.activate({
          manifestEntryId: "research.setup-disclosures",
          controlId: "research-setup-disclosures",
          option: disclosure.option,
          materialState: "Fixture required: a human-owned draft is bound to an attested synthetic-only Research execution boundary",
          modality: "pointer",
          testId: TEST_IDS.experimentControls,
        }, () => summary.click());
        await expect(control).toContainText(disclosure.expected);
        await summary.click();
        await interactionActivation.activate({
          manifestEntryId: "research.setup-disclosures",
          controlId: "research-setup-disclosures",
          option: disclosure.option,
          materialState: "Fixture required: a human-owned draft is bound to an attested synthetic-only Research execution boundary",
          modality: "keyboard",
          testId: TEST_IDS.experimentControls,
        }, () => summary.press("Enter"));
        await expect(control).toContainText(disclosure.expected);
      }

      const approval = control.getByRole("checkbox", {
        name: /I approve this exact charter, patch, fixture, and budget/u,
      });
      await interactionActivation.activate({
        manifestEntryId: "research.setup-approval",
        controlId: "research-setup-approval",
        option: "Approve the exact represented charter, patch, fixture, and budget",
        materialState: "Fixture required: a human-owned draft is bound to an attested synthetic-only Research execution boundary",
        modality: "pointer",
        testId: TEST_IDS.experimentControls,
      }, () => approval.click());
      await expect(approval).toBeChecked();
      await approval.click();
      await interactionActivation.activate({
        manifestEntryId: "research.setup-approval",
        controlId: "research-setup-approval",
        option: "Approve the exact represented charter, patch, fixture, and budget",
        materialState: "Fixture required: a human-owned draft is bound to an attested synthetic-only Research execution boundary",
        modality: "keyboard",
        testId: TEST_IDS.experimentControls,
      }, () => approval.press("Space"));
      await expect(approval).toBeChecked();

      const queue = control.getByRole("button", {
        name: "Approve and queue candidate",
        exact: true,
      });
      const queueReceipt = {
        manifestEntryId: "research.setup-queue",
        controlId: "research-setup-queue",
        option: "Approve and queue one exact synthetic development candidate",
        materialState: "Fixture required: the exact setup is reviewed, locally attested, and explicitly approved by the human campaign owner",
        modality,
        testId: TEST_IDS.experimentControls,
      } as const;
      let setupResponse: Response;
      if (index === 0) {
        const blocker = createDatabaseConnection({
          filename: fixture.databasePath,
          busyTimeoutMs: 100,
          verifyIntegrity: false,
        });
        blocker.exec("BEGIN IMMEDIATE");
        browserAudit.expectHttpResponse(page, {
          id: "research-lab.setup.store-busy",
          transport: "browser",
          method: "POST",
          pathname: `/api/v2/research/campaigns/${encodeURIComponent(campaignRecord.id)}/setup`,
          query: {},
          status: 503,
          occurrences: 2,
          reason: "Prove an initial setup and one exact-key retry remain bounded while the disposable Research store is reserved.",
        });
        try {
          const failedSetupPromise = page.waitForResponse((response) =>
            new URL(response.url()).pathname
              === `/api/v2/research/campaigns/${encodeURIComponent(campaignRecord.id)}/setup`
            && response.request().method() === "POST"
            && response.status() === 503);
          await interactionActivation.activate(queueReceipt, () => queue.click());
          const failedSetup = await failedSetupPromise;
          const setupKey = failedSetup.request().headers()["idempotency-key"];
          const setupBody = failedSetup.request().postDataJSON();
          expect(setupKey).toMatch(/^research-setup-[0-9a-f-]+$/u);
          expect(setupBody).toMatchObject({
            expectedUpdatedAt: campaignRecord.updatedAt,
            ownerApproval: true,
          });
          const alert = control.getByRole("alert").filter({
            hasText: "Research setup was not approved",
          });
          const retry = alert.getByRole("button", {
            name: "Try again",
            exact: true,
          });
          await expect(retry).toBeFocused();
          const blockedRetryPromise = page.waitForResponse((response) =>
            new URL(response.url()).pathname
              === `/api/v2/research/campaigns/${encodeURIComponent(campaignRecord.id)}/setup`
            && response.request().method() === "POST"
            && response.status() === 503);
          await interactionActivation.activate({
            manifestEntryId: "research.setup-retry",
            controlId: "research-setup-retry",
            option: "Retry the exact setup with its original idempotency key",
            materialState: "Fixture required: a real disposable-store write reservation returned retryable research_store_busy for the approved setup",
            modality: "keyboard",
            testId: TEST_IDS.experimentControls,
          }, () => retry.press("Enter"));
          const blockedRetry = await blockedRetryPromise;
          expect(blockedRetry.request().headers()["idempotency-key"]).toBe(setupKey);
          expect(blockedRetry.request().postDataJSON()).toEqual(setupBody);
          blocker.exec("ROLLBACK");
          const successfulRetryPromise = page.waitForResponse((response) =>
            new URL(response.url()).pathname
              === `/api/v2/research/campaigns/${encodeURIComponent(campaignRecord.id)}/setup`
            && response.request().method() === "POST"
            && response.status() === 201);
          await interactionActivation.activate({
            manifestEntryId: "research.setup-retry",
            controlId: "research-setup-retry",
            option: "Retry the exact setup with its original idempotency key",
            materialState: "Fixture required: a real disposable-store write reservation returned retryable research_store_busy for the approved setup",
            modality: "pointer",
            testId: TEST_IDS.experimentControls,
          }, () => retry.click());
          setupResponse = await successfulRetryPromise;
          expect(setupResponse.request().headers()["idempotency-key"]).toBe(setupKey);
          expect(setupResponse.request().postDataJSON()).toEqual(setupBody);
        } finally {
          try {
            blocker.exec("ROLLBACK");
          } catch {
            // The successful retry path has already released this reservation.
          }
          blocker.close();
        }
      } else {
        const successfulSetupPromise = page.waitForResponse((response) =>
          new URL(response.url()).pathname
            === `/api/v2/research/campaigns/${encodeURIComponent(campaignRecord.id)}/setup`
          && response.request().method() === "POST"
          && response.status() === 201);
        await interactionActivation.activate(
          queueReceipt,
          () => queue.press("Enter"),
        );
        setupResponse = await successfulSetupPromise;
      }
      expect(setupResponse.status(), await setupResponse.text()).toBe(201);
      const setupPayload = await setupResponse.json() as {
        setup: {
          experimentId: string;
          developmentScenarioId: string;
          candidateStrategyId: string;
          candidatePresetId: string;
          automaticPromotion: boolean;
          automaticDeployment: boolean;
        };
      };
      expect(setupPayload.setup).toMatchObject({
        candidatePresetId: `builtin-candidate-${campaign.id}-v1`,
        automaticPromotion: false,
        automaticDeployment: false,
      });

      const experimentRow = page.getByRole("row").filter({
        hasText: setupPayload.setup.candidateStrategyId,
      });
      await expect(experimentRow).toHaveCount(1);
      const seed = experimentRow.getByRole("textbox", {
        name: "Reproducible seed",
        exact: true,
      });
      const seedValue = `browser-${campaign.id}-${modality}`;
      await interactionActivation.activate({
        manifestEntryId: "research.experiment-seed",
        controlId: "research-experiment-seed",
        option: "Set a reproducible synthetic fixture seed",
        materialState: "Fixture required: a human-approved experiment is queued without an existing development run",
        modality,
        testId: TEST_IDS.experimentControls,
      }, async () => {
        if (modality === "pointer") {
          await seed.click();
          await seed.fill(seedValue);
        } else {
          await seed.focus();
          await seed.fill(seedValue);
        }
      });
      await expect(seed).toHaveValue(seedValue);

      const runResponsePromise = page.waitForResponse((response) =>
        new URL(response.url()).pathname
          === `/api/v2/research/experiments/${encodeURIComponent(setupPayload.setup.experimentId)}/runs`
        && response.request().method() === "POST"
        && response.status() === 202);
      const run = experimentRow.getByRole("button", {
        name: "Run development fixture",
        exact: true,
      });
      await interactionActivation.activate({
        manifestEntryId: "research.experiment-start",
        controlId: "research-experiment-start",
        option: "Queue the represented synthetic development fixture",
        materialState: "Fixture required: a valid reproducible seed is represented for a human-approved queued experiment",
        modality,
        testId: TEST_IDS.experimentControls,
      }, () => modality === "pointer" ? run.click() : run.press("Enter"));
      const runResponse = await runResponsePromise;
      expect(runResponse.request().headers()["idempotency-key"]).toMatch(
        /^research-run-[0-9a-f-]+$/u,
      );
      expect(runResponse.request().postDataJSON()).toEqual({
        scenarioId: setupPayload.setup.developmentScenarioId,
        seed: seedValue,
      });
      const runPayload = await runResponse.json() as {
        run: { id: string; status: string };
      };
      expect(runPayload.run.status).toBe("queued");

      const cancelReason = experimentRow.getByRole("textbox", {
        name: "Cancellation reason",
        exact: true,
      });
      const reasonValue = `Cancel the ${campaign.title} browser fixture after exact queue verification.`;
      await interactionActivation.activate({
        manifestEntryId: "research.experiment-cancel-reason",
        controlId: "research-experiment-cancel-reason",
        option: "Record why the exact queued or running fixture must stop",
        materialState: "Fixture required: the represented synthetic development run is queued or running",
        modality,
        testId: TEST_IDS.experimentControls,
      }, async () => {
        if (modality === "pointer") {
          await cancelReason.click();
          await cancelReason.fill(reasonValue);
        } else {
          await cancelReason.focus();
          await cancelReason.fill(reasonValue);
        }
      });
      const cancelResponsePromise = page.waitForResponse((response) =>
        new URL(response.url()).pathname
          === `/api/v2/research/experiments/${encodeURIComponent(setupPayload.setup.experimentId)}/runs/${encodeURIComponent(runPayload.run.id)}/cancel`
        && response.request().method() === "POST"
        && response.status() === 200);
      const cancel = experimentRow.getByRole("button", {
        name: "Cancel bounded run",
        exact: true,
      });
      await interactionActivation.activate({
        manifestEntryId: "research.experiment-cancel",
        controlId: "research-experiment-cancel",
        option: "Cancel the exact bounded synthetic run",
        materialState: "Fixture required: the represented synthetic run is active and has an attributable cancellation reason",
        modality,
        testId: TEST_IDS.experimentControls,
      }, () => modality === "pointer"
        ? cancel.click()
        : cancel.press("Enter"));
      const cancelResponse = await cancelResponsePromise;
      expect(cancelResponse.request().headers()["idempotency-key"]).toMatch(
        /^research-cancel-[0-9a-f-]+$/u,
      );
      expect(cancelResponse.request().postDataJSON()).toEqual({
        reason: reasonValue,
      });
      expect(await cancelResponse.json()).toMatchObject({
        run: { id: runPayload.run.id, status: "cancelled" },
      });
      await expect(experimentRow.getByText("cancelled", { exact: true }))
        .toBeVisible();
    }

    expect(fixture.database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM research_charters) AS charters,
        (SELECT COUNT(*) FROM experiments) AS experiments,
        (SELECT COUNT(*) FROM experiment_runs WHERE status = 'cancelled')
          AS cancelled_runs,
        (SELECT COUNT(*) FROM strategy_deployments) AS deployments,
        (SELECT COUNT(*) FROM provider_exposure_receipts) AS provider_exposures
    `).get()).toEqual({
      charters: 2,
      experiments: 2,
      cancelled_runs: 2,
      deployments: 0,
      provider_exposures: 0,
    });
  });
});

test(`${TEST_IDS.completedWorker} runs the attested local worker through authoritative development completion`, async ({
  page,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  await withExecutableResearchBrowserFixture(page, async (fixture) => {
    await page.goto("/learning?view=research", {
      waitUntil: "domcontentloaded",
    });
    await page.getByRole("checkbox", {
      name: /I own this campaign and its promotion decisions/u,
    }).check();
    const catalog = CAMPAIGNS[0];
    const card = campaignCard(page, catalog.title);
    const createResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research/campaigns"
      && response.request().method() === "POST"
      && response.status() === 201);
    await card.getByRole("button", {
      name: "Create bounded draft",
      exact: true,
    }).click();
    await expectCreateResponse(await createResponse, catalog.id);
    const control = card.locator(".os-research-control");
    await control.getByRole("checkbox", {
      name: /I approve this exact charter, patch, fixture, and budget/u,
    }).check();
    const setupResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname.endsWith("/setup")
      && response.request().method() === "POST"
      && response.status() === 201);
    await control.getByRole("button", {
      name: "Approve and queue candidate",
      exact: true,
    }).click();
    const setup = await (await setupResponse).json() as {
      readonly setup: {
        readonly experimentId: string;
        readonly developmentScenarioId: string;
        readonly candidateStrategyId: string;
      };
    };
    const experimentRow = page.getByRole("row").filter({
      hasText: setup.setup.candidateStrategyId,
    });
    const seedValue = "browser-authoritative-development-completion";
    await experimentRow.getByRole("textbox", {
      name: "Reproducible seed",
      exact: true,
    }).fill(seedValue);
    fixture.runner.start();
    const runResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname
        === `/api/v2/research/experiments/${encodeURIComponent(setup.setup.experimentId)}/runs`
      && response.request().method() === "POST"
      && response.status() === 202);
    await interactionActivation.activate({
      manifestEntryId: "research.experiment-start",
      controlId: "research-experiment-start",
      option: "Queue the represented synthetic development fixture",
      materialState:
        "Fixture required: a valid reproducible seed is represented for a human-approved queued experiment",
      modality: "pointer",
      testId: TEST_IDS.completedWorker,
    }, () => experimentRow.getByRole("button", {
      name: "Run development fixture",
      exact: true,
    }).click());
    const runAccepted = await runResponse;
    expect(runAccepted.request().postDataJSON()).toEqual({
      scenarioId: setup.setup.developmentScenarioId,
      seed: seedValue,
    });
    const accepted = await runAccepted.json() as {
      readonly run: { readonly id: string; readonly status: string };
    };
    expect(accepted.run.status).toBe("queued");

    await expect(experimentRow.getByText("completed", { exact: true }))
      .toBeVisible({ timeout: 30_000 });
    await expect(experimentRow).toContainText(
      "Development evaluated locally. Private holdout is still unavailable, so this result cannot promote.",
    );
    const promotion = page.locator(".os-research-promotions > .os-card").filter({
      has: page.getByRole("heading", {
        name: `Strategy ${setup.setup.candidateStrategyId}`,
        exact: true,
      }),
    });
    await expect(promotion).toHaveCount(1);
    await expect(promotion).toContainText("Development");
    await expect(promotion).toContainText("passed");

    expect(fixture.database.prepare(`
      SELECT status FROM experiment_runs WHERE id = ?
    `).get(accepted.run.id)).toEqual({ status: "completed" });
    expect(fixture.database.prepare(`
      SELECT status FROM research_experiment_admissions
      WHERE experiment_run_id = ?
    `).get(accepted.run.id)).toEqual({ status: "completed" });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM experiment_metrics
      WHERE experiment_run_id = ? AND authoritative = 1
    `).get(accepted.run.id)).toEqual({ count: 2 });
    expect(fixture.database.prepare(`
      SELECT execution_environment_kind, algorithm, evaluation_stage,
        evaluation_action, evaluation_result
      FROM integrity_receipts
      WHERE evaluation_attempt_id = ?
    `).get(accepted.run.id)).toEqual({
      execution_environment_kind: "local_bwrap",
      algorithm: "hmac-sha256",
      evaluation_stage: "development",
      evaluation_action: "development_pass",
      evaluation_result: "pass",
    });
    expect(fixture.database.prepare(`
      SELECT action FROM research_promotion_transitions
      WHERE experiment_id = ?
      ORDER BY sequence
    `).all(setup.setup.experimentId)).toEqual([
      { action: "policy_accept" },
      { action: "start_benchmark" },
      { action: "development_pass" },
    ]);
    expect(fixture.database.prepare(`
      SELECT receipt_kind, consumed_by_run_id
      FROM research_execution_receipts
      WHERE consumed_by_run_id = ?
      ORDER BY receipt_kind
    `).all(accepted.run.id)).toEqual([
      { receipt_kind: "lab", consumed_by_run_id: accepted.run.id },
      { receipt_kind: "worker", consumed_by_run_id: accepted.run.id },
    ]);
    expect(fixture.database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM strategy_deployments) AS deployments,
        (SELECT COUNT(*) FROM provider_exposure_receipts
          WHERE experiment_id = ?) AS provider_exposures,
        (SELECT COUNT(*) FROM benchmark_scenarios
          WHERE split = 'hidden_holdout') AS hidden_holdout_scenarios
    `).get(setup.setup.experimentId)).toEqual({
      deployments: 0,
      provider_exposures: 0,
      hidden_holdout_scenarios: 0,
    });
  });
});

test(`${TEST_IDS.experimentRetry} preserves exact start and cancellation intents across real store pressure`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(180_000);
  await withExecutableResearchBrowserFixture(page, async (fixture) => {
    await page.goto("/learning?view=research", {
      waitUntil: "domcontentloaded",
    });
    await page.getByRole("checkbox", {
      name: /I own this campaign and its promotion decisions/u,
    }).check();
    const experiment = await queueExecutableExperiment(page, 0);
    const seed = experiment.row.getByRole("textbox", {
      name: "Reproducible seed",
      exact: true,
    });
    await seed.fill("browser-exact-start-retry");
    const startPath =
      `/api/v2/research/experiments/${encodeURIComponent(experiment.experimentId)}/runs`;
    browserAudit.expectHttpResponse(page, {
      id: "research-lab.experiment-start.store-busy",
      transport: "browser",
      method: "POST",
      pathname: startPath,
      query: {},
      status: 503,
      occurrences: 4,
      reason:
        "Prove two explicit discards and both exact retry modalities while the disposable Research store is genuinely reserved.",
    });
    const startBlocker = createDatabaseConnection({
      filename: fixture.databasePath,
      busyTimeoutMs: 100,
      verifyIntegrity: false,
    });
    startBlocker.exec("BEGIN IMMEDIATE");
    try {
      for (const modality of ["pointer", "keyboard"] as const) {
        const failed = page.waitForResponse((response) =>
          new URL(response.url()).pathname === startPath
          && response.request().method() === "POST"
          && response.status() === 503);
        await experiment.row.getByRole("button", {
          name: "Run development fixture",
          exact: true,
        }).click();
        await failed;
        await expect(seed).toBeDisabled();
        const discard = experiment.row.getByRole("button", {
          name: "Discard retained request",
          exact: true,
        });
        await interactionActivation.activate({
          manifestEntryId: "research.experiment-discard-retained-request",
          controlId: "research-experiment-discard-retained-request",
          option: "Discard retained development-start request",
          materialState:
            "Fixture required: an exact start or cancellation request remains retained after failure, uncertainty, or canonical drift",
          modality,
          testId: TEST_IDS.experimentRetry,
        }, () => modality === "pointer"
          ? discard.click()
          : discard.press("Enter"));
        await expect(seed).toBeEnabled();
      }

      const initialFailure = page.waitForResponse((response) =>
        new URL(response.url()).pathname === startPath
        && response.request().method() === "POST"
        && response.status() === 503);
      await experiment.row.getByRole("button", {
        name: "Run development fixture",
        exact: true,
      }).click();
      const initialStart = await initialFailure;
      const startKey = initialStart.request().headers()["idempotency-key"];
      const startBody = initialStart.request().postData();
      expect(startKey).toMatch(/^research-run-[0-9a-f-]+$/u);
      expect(startBody).toBe(JSON.stringify({
        scenarioId: experiment.scenarioId,
        seed: "browser-exact-start-retry",
      }));
      const retry = experiment.row.getByRole("button", {
        name: "Try again",
        exact: true,
      });
      await expect(retry).toBeFocused();
      const blockedRetry = page.waitForResponse((response) =>
        new URL(response.url()).pathname === startPath
        && response.request().method() === "POST"
        && response.status() === 503);
      await interactionActivation.activate({
        manifestEntryId: "research.experiment-mutation-retry",
        controlId: "research-experiment-mutation-retry",
        option:
          "Retry exact development start with its original body and idempotency key",
        materialState:
          "Fixture required: an exact development-start or cancellation request failed retryably or its response was lost",
        modality: "keyboard",
        testId: TEST_IDS.experimentRetry,
      }, () => retry.press("Enter"));
      const blockedStartRetry = await blockedRetry;
      expect(blockedStartRetry.request().headers()["idempotency-key"])
        .toBe(startKey);
      expect(blockedStartRetry.request().postData()).toBe(startBody);
      startBlocker.exec("ROLLBACK");
      const successfulRetry = page.waitForResponse((response) =>
        new URL(response.url()).pathname === startPath
        && response.request().method() === "POST"
        && response.status() === 202);
      await interactionActivation.activate({
        manifestEntryId: "research.experiment-mutation-retry",
        controlId: "research-experiment-mutation-retry",
        option:
          "Retry exact development start with its original body and idempotency key",
        materialState:
          "Fixture required: an exact development-start or cancellation request failed retryably or its response was lost",
        modality: "pointer",
        testId: TEST_IDS.experimentRetry,
      }, () => retry.click());
      const acceptedStart = await successfulRetry;
      expect(acceptedStart.request().headers()["idempotency-key"])
        .toBe(startKey);
      expect(acceptedStart.request().postData()).toBe(startBody);
      const started = await acceptedStart.json() as {
        readonly run: { readonly id: string; readonly status: string };
      };
      expect(started.run.status).toBe("queued");

      const cancellationReason = experiment.row.getByRole("textbox", {
        name: "Cancellation reason",
        exact: true,
      });
      const reason =
        "Cancel after exact retry and idempotency verification completes.";
      await cancellationReason.fill(reason);
      const cancelPath =
        `${startPath}/${encodeURIComponent(started.run.id)}/cancel`;
      browserAudit.expectHttpResponse(page, {
        id: "research-lab.experiment-cancel.store-busy",
        transport: "browser",
        method: "POST",
        pathname: cancelPath,
        query: {},
        status: 503,
        occurrences: 4,
        reason:
          "Prove cancellation has no worker side effect before its durable reservation and preserves both exact retry modalities.",
      });
      const cancelBlocker = createDatabaseConnection({
        filename: fixture.databasePath,
        busyTimeoutMs: 100,
        verifyIntegrity: false,
      });
      cancelBlocker.exec("BEGIN IMMEDIATE");
      try {
        for (const modality of ["pointer", "keyboard"] as const) {
          const failed = page.waitForResponse((response) =>
            new URL(response.url()).pathname === cancelPath
            && response.request().method() === "POST"
            && response.status() === 503);
          await experiment.row.getByRole("button", {
            name: "Cancel bounded run",
            exact: true,
          }).click();
          await failed;
          await expect(cancellationReason).toBeDisabled();
          const discard = experiment.row.getByRole("button", {
            name: "Discard retained request",
            exact: true,
          });
          await interactionActivation.activate({
            manifestEntryId:
              "research.experiment-discard-retained-request",
            controlId: "research-experiment-discard-retained-request",
            option: "Discard retained cancellation request",
            materialState:
              "Fixture required: an exact start or cancellation request remains retained after failure, uncertainty, or canonical drift",
            modality,
            testId: TEST_IDS.experimentRetry,
          }, () => modality === "pointer"
            ? discard.click()
            : discard.press("Enter"));
          await expect(cancellationReason).toBeEnabled();
        }

        const initialCancelFailure = page.waitForResponse((response) =>
          new URL(response.url()).pathname === cancelPath
          && response.request().method() === "POST"
          && response.status() === 503);
        await experiment.row.getByRole("button", {
          name: "Cancel bounded run",
          exact: true,
        }).click();
        const initialCancel = await initialCancelFailure;
        const cancelKey =
          initialCancel.request().headers()["idempotency-key"];
        const cancelBody = initialCancel.request().postData();
        expect(cancelKey).toMatch(/^research-cancel-[0-9a-f-]+$/u);
        expect(cancelBody).toBe(JSON.stringify({ reason }));
        const cancelRetry = experiment.row.getByRole("button", {
          name: "Try again",
          exact: true,
        });
        const blockedCancel = page.waitForResponse((response) =>
          new URL(response.url()).pathname === cancelPath
          && response.request().method() === "POST"
          && response.status() === 503);
        await interactionActivation.activate({
          manifestEntryId: "research.experiment-mutation-retry",
          controlId: "research-experiment-mutation-retry",
          option:
            "Retry exact run cancellation with its original body and idempotency key",
          materialState:
            "Fixture required: an exact development-start or cancellation request failed retryably or its response was lost",
          modality: "pointer",
          testId: TEST_IDS.experimentRetry,
        }, () => cancelRetry.click());
        const blockedCancelRetry = await blockedCancel;
        expect(blockedCancelRetry.request().headers()["idempotency-key"])
          .toBe(cancelKey);
        expect(blockedCancelRetry.request().postData()).toBe(cancelBody);
        cancelBlocker.exec("ROLLBACK");
        const successfulCancel = page.waitForResponse((response) =>
          new URL(response.url()).pathname === cancelPath
          && response.request().method() === "POST"
          && response.status() === 200);
        await interactionActivation.activate({
          manifestEntryId: "research.experiment-mutation-retry",
          controlId: "research-experiment-mutation-retry",
          option:
            "Retry exact run cancellation with its original body and idempotency key",
          materialState:
            "Fixture required: an exact development-start or cancellation request failed retryably or its response was lost",
          modality: "keyboard",
          testId: TEST_IDS.experimentRetry,
        }, () => cancelRetry.press("Enter"));
        const cancelled = await successfulCancel;
        expect(cancelled.request().headers()["idempotency-key"])
          .toBe(cancelKey);
        expect(cancelled.request().postData()).toBe(cancelBody);
        expect(await cancelled.json()).toMatchObject({
          run: { id: started.run.id, status: "cancelled" },
        });
      } finally {
        try {
          cancelBlocker.exec("ROLLBACK");
        } catch {
          // The successful exact cancellation already released the lock.
        }
        cancelBlocker.close();
      }

      await expect(experiment.row.getByText("cancelled", { exact: true }))
        .toBeVisible();
      expect(fixture.database.prepare(`
        SELECT
          (SELECT COUNT(*) FROM experiment_runs
            WHERE experiment_id = ?) AS runs,
          (SELECT COUNT(*) FROM experiment_events
            WHERE experiment_id = ?
              AND event_type = 'experiment_run.cancelled')
            AS cancellation_events
      `).get(experiment.experimentId, experiment.experimentId)).toEqual({
        runs: 1,
        cancellation_events: 1,
      });
    } finally {
      try {
        startBlocker.exec("ROLLBACK");
      } catch {
        // The successful exact start already released the lock.
      }
      startBlocker.close();
    }
  });
});

test(`${TEST_IDS.experimentResponseLoss} reconciles committed start and cancellation outcomes without replay`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(180_000);
  for (const [campaignIndex, modality] of [
    [0, "pointer"],
    [1, "keyboard"],
  ] as const) {
    await withExecutableResearchBrowserFixture(page, async (fixture) => {
      await page.goto("/learning?view=research", {
        waitUntil: "domcontentloaded",
      });
      await page.getByRole("checkbox", {
        name: /I own this campaign and its promotion decisions/u,
      }).check();
      const experiment = await queueExecutableExperiment(
        page,
        campaignIndex,
      );
      const seedValue = `response-loss-${modality}`;
      const seed = experiment.row.getByRole("textbox", {
        name: "Reproducible seed",
        exact: true,
      });
      await seed.fill(seedValue);
      const startPath =
        `/api/v2/research/experiments/${encodeURIComponent(experiment.experimentId)}/runs`;
      let cancelPath: string | undefined;
      let queuedRun: ResearchExperimentRunRecord | undefined;
      let serveQueuedRun = false;
      let cancellationCommitted = false;
      let resolveStaleReadAfterCancellation!: () => void;
      const staleReadAfterCancellation = new Promise<void>(
        (resolveStaleRead) => {
          resolveStaleReadAfterCancellation = resolveStaleRead;
        },
      );
      let startPosts = 0;
      let cancelPosts = 0;
      let startForwarded:
        Awaited<ReturnType<typeof forwardResearchMutationAsLostResponse>>
        | undefined;
      let cancelForwarded:
        Awaited<ReturnType<typeof forwardResearchMutationAsLostResponse>>
        | undefined;

      await page.route("**/api/v2/research**", async (route) => {
        const request = route.request();
        const pathname = new URL(request.url()).pathname;
        if (
          request.method() === "POST"
          && pathname === startPath
        ) {
          startPosts += 1;
          if (startPosts === 1) {
            startForwarded =
              await forwardResearchMutationAsLostResponse({
                route,
                root: fixture.root,
                expectedStatus: 202,
              });
            return;
          }
        }
        if (
          cancelPath
          && request.method() === "POST"
          && pathname === cancelPath
        ) {
          cancelPosts += 1;
          if (cancelPosts === 1) {
            cancelForwarded =
              await forwardResearchMutationAsLostResponse({
                route,
                root: fixture.root,
                expectedStatus: 200,
              });
            cancellationCommitted = true;
            return;
          }
        }
        if (
          cancelPath
          && queuedRun
          && serveQueuedRun
          && request.method() === "GET"
          && pathname === cancelPath.replace(/\/cancel$/u, "")
        ) {
          await route.fulfill({
            status: 200,
            headers: {
              "content-type": "application/json; charset=utf-8",
            },
            body: JSON.stringify({
              schemaVersion: "2.4",
              run: queuedRun,
            }),
          });
          if (cancellationCommitted) {
            resolveStaleReadAfterCancellation();
          }
          return;
        }
        await route.fallback();
      });

      const startResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === startPath
        && response.request().method() === "POST"
        && response.status() === 202);
      await experiment.row.getByRole("button", {
        name: "Run development fixture",
        exact: true,
      }).click();
      await startResponse;
      await expect(experiment.row.getByRole("alert").filter({
        hasText: "Research development run did not start",
      })).toBeVisible();
      expect(startPosts).toBe(1);
      expect(startForwarded).toBeDefined();
      expect(startForwarded?.idempotencyKey)
        .toMatch(/^research-run-[0-9a-f-]+$/u);
      expect(startForwarded?.serializedBody).toBe(JSON.stringify({
        scenarioId: experiment.scenarioId,
        seed: seedValue,
      }));
      expect(startForwarded?.canonical.run.status).toBe("queued");
      expect(await page.evaluate((experimentId) => {
        const key = Object.keys(sessionStorage).find((candidate) =>
          candidate.includes(encodeURIComponent(experimentId)));
        return key ? JSON.parse(sessionStorage.getItem(key) ?? "null") : null;
      }, experiment.experimentId)).toMatchObject({
        action: "start",
        disposition: "uncertain",
        idempotencyKey: startForwarded?.idempotencyKey,
        serializedBody: startForwarded?.serializedBody,
      });

      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.reload({ waitUntil: "domcontentloaded" }),
      );
      const restoredStartRefresh = experiment.row.getByRole("button", {
        name: "Refresh canonical run state",
        exact: true,
      });
      await expect(restoredStartRefresh).toBeVisible();
      await expect(experiment.row.getByRole("button", {
        name: "Try again",
        exact: true,
      })).toHaveCount(0);
      const startCanonicalRead = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/api/v2/research"
        && response.request().method() === "GET"
        && response.status() === 200);
      await interactionActivation.activate({
        manifestEntryId: "research.experiment-canonical-refresh",
        controlId: "research-experiment-canonical-refresh",
        option:
          "Refresh canonical state after an uncertain development start",
        materialState:
          "Fixture required: an exact retained start or cancellation outcome is uncertain or conflicts with the visible canonical run",
        modality,
        testId: TEST_IDS.experimentResponseLoss,
      }, () => modality === "pointer"
        ? restoredStartRefresh.click()
        : restoredStartRefresh.press("Enter"));
      await startCanonicalRead;
      await expect(experiment.row).toContainText(
        "Canonical state contains the bounded run. The start request was not repeated.",
      );
      expect(startPosts).toBe(1);
      expect(await page.evaluate((experimentId) =>
        Object.keys(sessionStorage).some((candidate) =>
          candidate.includes(encodeURIComponent(experimentId))),
      experiment.experimentId)).toBe(false);

      const runId = startForwarded!.canonical.run.id;
      queuedRun = fixture.runner.read(runId);
      expect(queuedRun.status).toBe("queued");
      cancelPath =
        `${startPath}/${encodeURIComponent(runId)}/cancel`;
      serveQueuedRun = true;
      const cancellationReason =
        `Response-loss cancellation verified by ${modality}.`;
      await experiment.row.getByRole("textbox", {
        name: "Cancellation reason",
        exact: true,
      }).fill(cancellationReason);
      const cancelResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === cancelPath
        && response.request().method() === "POST"
        && response.status() === 200);
      await experiment.row.getByRole("button", {
        name: "Cancel bounded run",
        exact: true,
      }).click();
      await cancelResponse;
      await expect(experiment.row.getByRole("alert").filter({
        hasText: "Research run control failed",
      })).toBeVisible();
      expect(cancelPosts).toBe(1);
      expect(cancelForwarded).toBeDefined();
      expect(cancelForwarded?.idempotencyKey)
        .toMatch(/^research-cancel-[0-9a-f-]+$/u);
      expect(cancelForwarded?.serializedBody).toBe(JSON.stringify({
        reason: cancellationReason,
      }));
      expect(cancelForwarded?.canonical.run).toMatchObject({
        id: runId,
        status: "cancelled",
      });
      expect(await page.evaluate((experimentId) => {
        const key = Object.keys(sessionStorage).find((candidate) =>
          candidate.includes(encodeURIComponent(experimentId)));
        return key ? JSON.parse(sessionStorage.getItem(key) ?? "null") : null;
      }, experiment.experimentId)).toMatchObject({
        action: "cancel",
        disposition: "uncertain",
        idempotencyKey: cancelForwarded?.idempotencyKey,
        serializedBody: cancelForwarded?.serializedBody,
      });

      // The retained uncertain cancellation now suspends ordinary polling.
      // A request that was already in flight may still return, so exercise
      // either outcome without requiring a stale read that the product is
      // specifically designed to prevent.
      await Promise.race([
        staleReadAfterCancellation,
        page.waitForTimeout(900),
      ]);
      const cancelRefresh = experiment.row.getByRole("button", {
        name: "Refresh canonical run state",
        exact: true,
      });
      await expect(cancelRefresh).toBeVisible();
      serveQueuedRun = false;
      const cancelCanonicalRead = page.waitForResponse((response) =>
        new URL(response.url()).pathname
          === cancelPath!.replace(/\/cancel$/u, "")
        && response.request().method() === "GET"
        && response.status() === 200);
      await interactionActivation.activate({
        manifestEntryId: "research.experiment-canonical-refresh",
        controlId: "research-experiment-canonical-refresh",
        option:
          "Refresh canonical state after an uncertain cancellation",
        materialState:
          "Fixture required: an exact retained start or cancellation outcome is uncertain or conflicts with the visible canonical run",
        modality,
        testId: TEST_IDS.experimentResponseLoss,
      }, () => modality === "pointer"
        ? cancelRefresh.click()
        : cancelRefresh.press("Enter"));
      await cancelCanonicalRead;
      await expect(experiment.row).toContainText(
        "Canonical state confirms the run ended. The cancellation request was not repeated.",
      );
      expect(startPosts).toBe(1);
      expect(cancelPosts).toBe(1);
      expect(await page.evaluate((experimentId) =>
        Object.keys(sessionStorage).some((candidate) =>
          candidate.includes(encodeURIComponent(experimentId))),
      experiment.experimentId)).toBe(false);
      expect(fixture.database.prepare(`
        SELECT
          (SELECT COUNT(*) FROM experiment_runs
            WHERE experiment_id = ?) AS runs,
          (SELECT COUNT(*) FROM experiment_events
            WHERE experiment_id = ?
              AND event_type = 'experiment_run.cancelled')
            AS cancellation_events
      `).get(experiment.experimentId, experiment.experimentId)).toEqual({
        runs: 1,
        cancellation_events: 1,
      });
    });
  }
});

test(`${TEST_IDS.retryable} preserves exact create and stop intents across real retryable store pressure`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(180_000);
  let databaseLock: ReturnType<typeof holdResearchLabWriteLock> | undefined;
  try {
    await page.goto("/learning?view=research", { waitUntil: "domcontentloaded" });
    const ownership = page.getByRole("checkbox", { name: /I own this campaign and its promotion decisions/u });
    await ownership.check();
    const catalog = CAMPAIGNS[0];
    const card = campaignCard(page, catalog.title);

    databaseLock = holdResearchLabWriteLock();
    browserAudit.expectHttpResponse(page, {
      id: "research-lab.create.store-busy",
      transport: "browser",
      method: "POST",
      pathname: "/api/v2/research/campaigns",
      query: {},
      status: 503,
      occurrences: 2,
      reason: "Prove an initial create and one exact-key retry remain bounded while the real SQLite write reservation is held.",
    });
    const createFailurePromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research/campaigns"
      && response.request().method() === "POST"
      && response.status() === 503);
    await card.getByRole("button", { name: "Create bounded draft", exact: true }).click();
    const createFailure = await createFailurePromise;
    const createKey = createFailure.request().headers()["idempotency-key"];
    const createBody = createFailure.request().postDataJSON();
    expect(await createFailure.json()).toMatchObject({
      error: {
        code: "research_store_busy",
        retryable: true,
        humanMessage: "Another local operation is briefly updating the Research Lab.",
        remediation: "Try this exact change again; Ti-Scale will reuse its original submission key.",
      },
    });
    const createAlert = page.getByRole("alert").filter({ hasText: "Research campaign was not created" });
    await expect(createAlert).toContainText("Another local operation is briefly updating the Research Lab.");
    await expect(page.getByText("Try again resubmits the exact represented request with its original idempotency key.", { exact: false })).toBeVisible();
    const createRetry = createAlert.getByRole("button", { name: "Try again", exact: true });
    await expect(createRetry).toBeFocused();
    await expect(card.getByRole("button", { name: "Create bounded draft", exact: true })).toBeDisabled();
    const blockedCreateRetryRequest = page.waitForRequest((request) =>
      new URL(request.url()).pathname === "/api/v2/research/campaigns"
      && request.method() === "POST");
    const blockedCreateRetryResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research/campaigns"
      && response.request().method() === "POST"
      && response.status() === 503);
    await interactionActivation.activate({
      manifestEntryId: "research.mutation-retry",
      controlId: "research-mutation-retry",
      option: "Retry campaign creation with the original idempotency key",
      materialState: "Fixture required: a real SQLite write reservation causes one create or stop mutation to return the retryable research_store_busy envelope",
      modality: "keyboard",
      testId: TEST_IDS.retryable,
    }, () => createRetry.press("Enter"));
    const blockedCreateRequest = await blockedCreateRetryRequest;
    expect(blockedCreateRequest.headers()["idempotency-key"]).toBe(createKey);
    expect(blockedCreateRequest.postDataJSON()).toEqual(createBody);
    expect((await blockedCreateRetryResponse).status()).toBe(503);
    databaseLock.release();
    databaseLock = undefined;

    const createPointerRetry = createAlert.getByRole("button", { name: "Try again", exact: true });
    await expect(createPointerRetry).toBeFocused();
    const createRetryRequest = page.waitForRequest((request) =>
      new URL(request.url()).pathname === "/api/v2/research/campaigns"
      && request.method() === "POST");
    const createRetryResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research/campaigns"
      && response.request().method() === "POST"
      && response.status() === 201);
    await interactionActivation.activate({
      manifestEntryId: "research.mutation-retry",
      controlId: "research-mutation-retry",
      option: "Retry campaign creation with the original idempotency key",
      materialState: "Fixture required: a real SQLite write reservation causes one create or stop mutation to return the retryable research_store_busy envelope",
      modality: "pointer",
      testId: TEST_IDS.retryable,
    }, () => createPointerRetry.click());
    const retriedCreateRequest = await createRetryRequest;
    expect(retriedCreateRequest.headers()["idempotency-key"]).toBe(createKey);
    expect(retriedCreateRequest.postDataJSON()).toEqual(createBody);
    const campaign = await expectCreateResponse(await createRetryResponse, catalog.id);

    await expect(card.getByText("draft", { exact: true })).toBeVisible();
    const controls = card.locator(".os-research-control");
    await controls.locator("summary").filter({ hasText: "Stop campaign" }).click();
    const reasonText = "Stop after retry-boundary verification; no charter or experiment was approved.";
    await controls.getByRole("textbox", { name: "Reason for stopping", exact: true }).fill(reasonText);

    databaseLock = holdResearchLabWriteLock();
    browserAudit.expectHttpResponse(page, {
      id: "research-lab.stop.store-busy",
      transport: "browser",
      method: "POST",
      pathname: `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`,
      query: {},
      status: 503,
      occurrences: 2,
      reason: "Prove an initial stop and one exact-key retry preserve the represented version, reason, and key while SQLite remains reserved.",
    });
    const stopFailurePromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && response.request().method() === "POST"
      && response.status() === 503);
    await controls.getByRole("button", { name: "Stop campaign", exact: true }).click();
    const stopFailure = await stopFailurePromise;
    const stopKey = stopFailure.request().headers()["idempotency-key"];
    const stopBody = stopFailure.request().postDataJSON();
    const stopAlert = controls.getByRole("alert").filter({ hasText: "Campaign was not stopped" });
    await expect(stopAlert).toContainText("Another local operation is briefly updating the Research Lab.");
    const stopRetry = stopAlert.getByRole("button", { name: "Try again", exact: true });
    await expect(stopRetry).toBeFocused();
    await expect(controls.getByRole("button", { name: "Stop campaign", exact: true })).toBeDisabled();
    const blockedStopRetryRequest = page.waitForRequest((request) =>
      new URL(request.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && request.method() === "POST");
    const blockedStopRetryResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && response.request().method() === "POST"
      && response.status() === 503);
    await interactionActivation.activate({
      manifestEntryId: "research.mutation-retry",
      controlId: "research-mutation-retry",
      option: "Retry campaign stop with the original idempotency key",
      materialState: "Fixture required: a real SQLite write reservation causes one create or stop mutation to return the retryable research_store_busy envelope",
      modality: "keyboard",
      testId: TEST_IDS.retryable,
    }, () => stopRetry.press("Enter"));
    const blockedStopRequest = await blockedStopRetryRequest;
    expect(blockedStopRequest.headers()["idempotency-key"]).toBe(stopKey);
    expect(blockedStopRequest.postDataJSON()).toEqual(stopBody);
    expect((await blockedStopRetryResponse).status()).toBe(503);
    databaseLock.release();
    databaseLock = undefined;

    const stopPointerRetry = stopAlert.getByRole("button", { name: "Try again", exact: true });
    await expect(stopPointerRetry).toBeFocused();
    const stopRetryRequest = page.waitForRequest((request) =>
      new URL(request.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && request.method() === "POST");
    const stopRetryResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && response.request().method() === "POST"
      && response.status() === 200);
    await interactionActivation.activate({
      manifestEntryId: "research.mutation-retry",
      controlId: "research-mutation-retry",
      option: "Retry campaign stop with the original idempotency key",
      materialState: "Fixture required: a real SQLite write reservation causes one create or stop mutation to return the retryable research_store_busy envelope",
      modality: "pointer",
      testId: TEST_IDS.retryable,
    }, () => stopPointerRetry.click());
    const retriedStopRequest = await stopRetryRequest;
    expect(retriedStopRequest.headers()["idempotency-key"]).toBe(stopKey);
    expect(retriedStopRequest.postDataJSON()).toEqual(stopBody);
    expect((await stopRetryResponse).status()).toBe(200);
    await expect(card.getByRole("button", { name: "Create bounded draft", exact: true })).toBeVisible();

    expect(readResearchCampaignFixtureState(campaign.id)).toMatchObject({
      status: "stopped",
      createAuditCount: 1,
      stopAuditCount: 1,
      charterCount: 0,
      experimentCount: 0,
    });
  } finally {
    databaseLock?.release();
  }
});

test(`${TEST_IDS.conflict} reconciles a real optimistic stop conflict before a new reviewed submission`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  await page.goto("/learning?view=research", { waitUntil: "domcontentloaded" });
    await page.getByRole("checkbox", { name: /I own this campaign and its promotion decisions/u }).check();
    const catalog = CAMPAIGNS[1];
    const card = campaignCard(page, catalog.title);
    const createResponsePromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research/campaigns"
      && response.request().method() === "POST");
    await card.getByRole("button", { name: "Create bounded draft", exact: true }).click();
    const campaign = await expectCreateResponse(await createResponsePromise, catalog.id);
    const concurrentUpdatedAt = advanceResearchCampaignVersion(campaign.id);

    const controls = card.locator(".os-research-control");
    await controls.locator("summary").filter({ hasText: "Stop campaign" }).click();
    const reasonText = "The human owner reviewed a newer campaign version before stopping it.";
    const reason = controls.getByRole("textbox", { name: "Reason for stopping", exact: true });
    await reason.fill(reasonText);
    browserAudit.expectHttpResponse(page, {
      id: "research-lab.stop.version-conflict",
      transport: "browser",
      method: "POST",
      pathname: `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`,
      query: {},
      status: 409,
      occurrences: 2,
      reason: "Prove both pointer and keyboard reconciliation paths begin from a real stale-version denial.",
    });
    const conflictResponsePromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && response.request().method() === "POST"
      && response.status() === 409);
    await controls.getByRole("button", { name: "Stop campaign", exact: true }).click();
    const conflictResponse = await conflictResponsePromise;
    const staleKey = conflictResponse.request().headers()["idempotency-key"];
    expect(conflictResponse.request().postDataJSON()).toMatchObject({ expectedUpdatedAt: campaign.updatedAt, reason: reasonText });
    expect(await conflictResponse.json()).toMatchObject({
      error: {
        code: "research_campaign_version_conflict",
        retryable: false,
        humanMessage: "The campaign changed after this view loaded.",
        remediation: "Refresh the Research Lab and review the current campaign state.",
      },
    });

    const alert = controls.getByRole("alert").filter({ hasText: "Campaign was not stopped" });
    await expect(alert).toContainText("The campaign changed after this view loaded.");
    await expect(alert.getByRole("button", { name: "Try again", exact: true })).toHaveCount(0);
    const refresh = controls.getByRole("button", { name: "Refresh campaign state", exact: true });
    await expect(refresh).toBeFocused();
    await expect(controls.getByRole("button", { name: "Stop campaign", exact: true })).toBeDisabled();
    const refreshResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research"
      && response.request().method() === "GET"
      && response.status() === 200);
    await interactionActivation.activate({
      manifestEntryId: "research.mutation-refresh",
      controlId: "research-mutation-refresh",
      option: "Refresh after optimistic campaign-version conflict",
      materialState: "Fixture required: the represented stop timestamp is stale after a concurrent canonical campaign update",
      modality: "pointer",
      testId: TEST_IDS.conflict,
    }, () => refresh.click());
    const refreshedPayload = await (await refreshResponse).json() as {
      readonly campaigns: readonly { readonly id: string; readonly updatedAt: string }[];
    };
    expect(refreshedPayload.campaigns.find(({ id }) => id === campaign.id)?.updatedAt).toBe(concurrentUpdatedAt);
    await expect(controls.getByRole("button", { name: "Refresh campaign state", exact: true })).toHaveCount(0);
    await expect(reason).toHaveValue(reasonText);

    const secondConcurrentUpdatedAt = advanceResearchCampaignVersion(campaign.id);
    const secondConflictResponsePromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && response.request().method() === "POST"
      && response.status() === 409);
    await controls.getByRole("button", { name: "Stop campaign", exact: true }).click();
    const secondConflictResponse = await secondConflictResponsePromise;
    const secondStaleKey = secondConflictResponse.request().headers()["idempotency-key"];
    expect(secondStaleKey).not.toBe(staleKey);
    expect(secondConflictResponse.request().postDataJSON()).toEqual({
      expectedUpdatedAt: concurrentUpdatedAt,
      reason: reasonText,
    });
    const keyboardRefresh = controls.getByRole("button", { name: "Refresh campaign state", exact: true });
    await expect(keyboardRefresh).toBeFocused();
    const secondRefreshResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/research"
      && response.request().method() === "GET"
      && response.status() === 200);
    await interactionActivation.activate({
      manifestEntryId: "research.mutation-refresh",
      controlId: "research-mutation-refresh",
      option: "Refresh after optimistic campaign-version conflict",
      materialState: "Fixture required: the represented stop timestamp is stale after a concurrent canonical campaign update",
      modality: "keyboard",
      testId: TEST_IDS.conflict,
    }, () => keyboardRefresh.press("Enter"));
    const secondRefreshedPayload = await (await secondRefreshResponse).json() as {
      readonly campaigns: readonly { readonly id: string; readonly updatedAt: string }[];
    };
    expect(secondRefreshedPayload.campaigns.find(({ id }) => id === campaign.id)?.updatedAt).toBe(secondConcurrentUpdatedAt);
    await expect(reason).toHaveValue(reasonText);

    const reviewedRequest = page.waitForRequest((request) =>
      new URL(request.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && request.method() === "POST");
    const reviewedResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === `/api/v2/research/campaigns/${encodeURIComponent(campaign.id)}/stop`
      && response.request().method() === "POST"
      && response.status() === 200);
    await controls.getByRole("button", { name: "Stop campaign", exact: true }).click();
    const reviewed = await reviewedRequest;
    expect(reviewed.headers()["idempotency-key"]).not.toBe(staleKey);
    expect(reviewed.headers()["idempotency-key"]).not.toBe(secondStaleKey);
    expect(reviewed.postDataJSON()).toEqual({ expectedUpdatedAt: secondConcurrentUpdatedAt, reason: reasonText });
    expect((await reviewedResponse).status()).toBe(200);
  expect(readResearchCampaignFixtureState(campaign.id)).toMatchObject({
    status: "stopped",
    createAuditCount: 1,
    stopAuditCount: 1,
    charterCount: 0,
    experimentCount: 0,
  });
});

test(`${TEST_IDS.promotion} advances signed holdout through human review, isolated shadow, bounded canary, verification, and forward rollback`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(180_000);
  let fixture: ResearchPromotionLifecycleFixture | undefined;
  const candidateCard = () => page
    .locator(".os-research-promotions > .os-card")
    .filter({
      has: page.getByRole("heading", {
        name: fixture ? `Strategy ${fixture.candidateStrategyId}` : "unseeded",
        exact: true,
      }),
    });
  const reloadResearch = async (): Promise<void> => {
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.reload({ waitUntil: "domcontentloaded" }),
    );
  };
  const fillDecision = async (rationale: string): Promise<void> => {
    const card = candidateCard();
    await card.getByRole("textbox", {
      name: "Decision rationale",
      exact: true,
    }).fill(rationale);
    const evidence = card.getByRole("textbox", {
      name: "Evidence or receipt references",
      exact: true,
    });
    if ((await evidence.inputValue()).trim().length === 0) {
      await evidence.fill(`evaluation-${fixture?.candidateExperimentId}`);
    }
  };
  const transition = async (
    label: string,
    action: string,
    rationale: string,
    modality: "pointer" | "keyboard" = "pointer",
  ): Promise<Record<string, unknown>> => {
    await fillDecision(rationale);
    const responsePromise = page.waitForResponse((response) =>
      new URL(response.url()).pathname
        === `/api/v2/research/experiments/${encodeURIComponent(fixture!.candidateExperimentId)}/promotion`
      && response.request().method() === "POST");
    const button = candidateCard().getByRole("button", {
      name: label,
      exact: true,
    });
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-actions",
      controlId: "research-promotion-actions",
      option: label,
      materialState: PROMOTION_ACTION_MATERIAL_STATE,
      modality,
      testId: TEST_IDS.promotion,
    }, () => modality === "pointer" ? button.click() : button.press("Enter"));
    const response = await responsePromise;
    expect(response.status(), await response.text()).toBe(200);
    expect(response.request().headers()["idempotency-key"]).toMatch(
      /^research-promotion-[0-9a-f-]+$/u,
    );
    const request = response.request().postDataJSON() as {
      readonly action: string;
      readonly expectedVersion: number;
      readonly rationale: string;
      readonly evidenceRefs: readonly string[];
    };
    expect(request.action).toBe(action);
    expect(request.expectedVersion).toBeGreaterThan(0);
    expect(request.rationale).toBe(rationale);
    expect(request.evidenceRefs.length).toBeGreaterThan(0);
    const body = await response.json() as {
      readonly lifecycle?: { readonly state?: string };
      readonly [key: string]: unknown;
    };
    const canonicalState = body.lifecycle?.state;
    expect(canonicalState).toBeTruthy();
    await expect(candidateCard().getByText(canonicalState!, {
      exact: true,
    }).first()).toBeVisible();
    return body;
  };

  try {
    fixture = seedResearchPromotionLifecycleFixture();
    await page.goto("/learning?view=research", {
      waitUntil: "domcontentloaded",
    });
    const card = candidateCard();
    await expect(card).toHaveCount(1);
    await expect(card.getByText("human review", { exact: true })).toBeVisible();
    const history = card.locator("summary").filter({
      hasText: "Immutable transition history",
    });
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-history",
      controlId: "research-promotion-history",
      option: "Open or close the signed lifecycle transition history",
      materialState: "A durable candidate promotion lifecycle is present",
      modality: "pointer",
      testId: TEST_IDS.promotion,
    }, () => history.click());
    await expect(card).toContainText("hidden_holdout_pass");
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-history",
      controlId: "research-promotion-history",
      option: "Open or close the signed lifecycle transition history",
      materialState: "A durable candidate promotion lifecycle is present",
      modality: "keyboard",
      testId: TEST_IDS.promotion,
    }, () => history.press("Enter"));
    const rationale = card.getByRole("textbox", {
      name: "Decision rationale",
      exact: true,
    });
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-rationale",
      controlId: "research-promotion-rationale",
      option: "Record a readable rationale for the represented transition",
      materialState: "At least one human action is valid for the candidate",
      modality: "pointer",
      testId: TEST_IDS.promotion,
    }, async () => {
      await rationale.click();
      await rationale.fill("Pointer-authored signed holdout review.");
    });
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-rationale",
      controlId: "research-promotion-rationale",
      option: "Record a readable rationale for the represented transition",
      materialState: "At least one human action is valid for the candidate",
      modality: "keyboard",
      testId: TEST_IDS.promotion,
    }, async () => {
      await rationale.focus();
      await rationale.press("ControlOrMeta+A");
      await rationale.pressSequentially("Keyboard-authored signed holdout review.");
    });
    const evidence = card.getByRole("textbox", {
      name: "Evidence or receipt references",
      exact: true,
    });
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-evidence",
      controlId: "research-promotion-evidence",
      option: "Record comma- or newline-separated stable evidence and receipt IDs",
      materialState: "At least one human action is valid for the candidate",
      modality: "pointer",
      testId: TEST_IDS.promotion,
    }, async () => {
      await evidence.click();
      await evidence.fill("pointer-evidence-receipt");
    });
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-evidence",
      controlId: "research-promotion-evidence",
      option: "Record comma- or newline-separated stable evidence and receipt IDs",
      materialState: "At least one human action is valid for the candidate",
      modality: "keyboard",
      testId: TEST_IDS.promotion,
    }, async () => {
      await evidence.focus();
      await evidence.press("ControlOrMeta+A");
      await evidence.pressSequentially("keyboard-evidence-receipt");
    });

    await transition(
      "Approve for isolated shadow",
      "approve_human_review",
      "Signed holdout results passed every immutable hard gate.",
    );
    await reloadResearch();
    await transition(
      "Start isolated shadow",
      "start_shadow",
      "Run the candidate without any live mission execution effect.",
    );
    expect(readResearchPromotionFixtureState(fixture).deployments).toContainEqual({
      deploymentStage: "shadow",
      isolationMode: "no_live_effect",
      maxMissions: null,
      maxWallClockMs: null,
      status: "running",
    });

    recordResearchPromotionEvaluatorPass(fixture, "shadow_pass");
    await reloadResearch();
    await expect(candidateCard().getByText("shadow_running", {
      exact: true,
    })).toBeVisible();
    await expect(candidateCard().getByRole("button", {
      name: "Approve bounded canary",
      exact: true,
    })).toBeVisible();
    await transition(
      "Approve bounded canary",
      "approve_canary",
      "The isolated shadow preserved policy, evidence, and objective quality.",
    );
    await reloadResearch();
    const canaryCard = candidateCard();
    const maxMissionsInput = canaryCard.getByRole("spinbutton", {
      name: "Maximum missions",
      exact: true,
    });
    const maxMinutesInput = canaryCard.getByRole("spinbutton", {
      name: "Maximum minutes",
      exact: true,
    });
    for (const [option, input, value] of [
      ["Set maximum missions", maxMissionsInput, "2"],
      ["Set maximum minutes", maxMinutesInput, "30"],
    ] as const) {
      await interactionActivation.activate({
        manifestEntryId: "research.promotion-canary-bounds",
        controlId: "research-promotion-canary-bounds",
        option,
        materialState: "The candidate passed shadow and the human reviewer approved canary",
        modality: "pointer",
        testId: TEST_IDS.promotion,
      }, async () => {
        await input.click();
        await input.fill(value);
      });
      await interactionActivation.activate({
        manifestEntryId: "research.promotion-canary-bounds",
        controlId: "research-promotion-canary-bounds",
        option,
        materialState: "The candidate passed shadow and the human reviewer approved canary",
        modality: "keyboard",
        testId: TEST_IDS.promotion,
      }, async () => {
        await input.focus();
        await input.press("ControlOrMeta+A");
        await input.pressSequentially(value);
      });
    }
    const canaryResponse = await transition(
      "Start bounded canary",
      "start_canary",
      "Limit the canary to two disposable missions and thirty minutes.",
    );
    expect(canaryResponse).toMatchObject({
      lifecycle: { state: "canary_running" },
    });
    expect(readResearchPromotionFixtureState(fixture).deployments).toContainEqual({
      deploymentStage: "canary",
      isolationMode: "bounded_canary",
      maxMissions: 2,
      maxWallClockMs: 1_800_000,
      status: "running",
    });

    recordResearchPromotionEvaluatorPass(fixture, "canary_pass");
    await reloadResearch();
    await transition(
      "Verify strategy",
      "verify",
      "The bounded canary passed with no regression or disclosure violation.",
    );
    await expect(candidateCard().getByRole("status")).toContainText(
      "No production deployment was created.",
    );
    let state = readResearchPromotionFixtureState(fixture);
    expect(state.state).toBe("verified");
    expect(state.deployments.some(({ deploymentStage }) =>
      deploymentStage === "verified")).toBe(false);
    expect(state.activations.at(-1)).toEqual({
      ordinal: 2,
      action: "verified_selection",
      selectedStrategyVersionId: fixture.candidateStrategyId,
    });
    const strategyCountBeforeRollback = state.strategyVersionCount;

    await reloadResearch();
    const priorTarget = candidateCard().getByRole("radio", {
      name: new RegExp(fixture.priorStrategyId, "u"),
    });
    const rollbackTargetOption = "Choose a different previously verified strategy";
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-rollback-target",
      controlId: "research-promotion-rollback-target",
      option: rollbackTargetOption,
      materialState: "A current candidate and a different previously verified campaign strategy exist",
      modality: "pointer",
      testId: TEST_IDS.promotion,
    }, () => priorTarget.check());
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-rollback-target",
      controlId: "research-promotion-rollback-target",
      option: rollbackTargetOption,
      materialState: "A current candidate and a different previously verified campaign strategy exist",
      modality: "keyboard",
      testId: TEST_IDS.promotion,
    }, async () => {
      await priorTarget.focus();
      await priorTarget.press("Space");
    });
    await transition(
      "Roll back by forward activation",
      "rollback",
      "Select the prior verified strategy through a new immutable activation.",
    );
    state = readResearchPromotionFixtureState(fixture);
    expect(state.state).toBe("rolled_back");
    expect(state.rollbackCount).toBe(1);
    expect(state.strategyVersionCount).toBe(strategyCountBeforeRollback);
    expect(state.activations.at(-1)).toEqual({
      ordinal: 3,
      action: "forward_rollback",
      selectedStrategyVersionId: fixture.priorStrategyId,
    });
    expect(state.transitionActions).toEqual([
      "policy_accept",
      "start_benchmark",
      "development_pass",
      "validation_pass",
      "hidden_holdout_pass",
      "approve_human_review",
      "start_shadow",
      "shadow_pass",
      "approve_canary",
      "start_canary",
      "canary_pass",
      "verify",
      "rollback",
    ]);
  } finally {
    if (fixture) completeResearchPromotionLifecycleFixture(fixture);
  }
});

test(`${TEST_IDS.promotionActions} activates every remaining human promotion option by pointer and keyboard`, async ({
  page,
  interactionActivation,
}) => {
  test.setTimeout(240_000);
  let fixture: ResearchPromotionActionMatrixFixture | undefined;
  try {
    fixture = seedResearchPromotionActionMatrixFixture();
    await page.goto("/learning?view=research", {
      waitUntil: "domcontentloaded",
    });
    // The rollback fixture is the latest immutable activation at seed time.
    // Exercise it before the separate verify action appends a newer selection.
    const candidates = [
      ...fixture.actionCandidates.filter(({ action }) => action === "rollback"),
      ...fixture.actionCandidates.filter(({ action }) => action !== "rollback"),
    ];
    for (const candidate of candidates) {
      const card = page
        .locator(".os-research-promotions > .os-card")
        .filter({
          has: page.getByRole("heading", {
            name: `Strategy ${candidate.strategyId}`,
            exact: true,
          }),
        });
      await expect(card).toHaveCount(1);
      const rationale = card.getByRole("textbox", {
        name: "Decision rationale",
        exact: true,
      });
      const review =
        `${candidate.action.replaceAll("_", " ")} reviewed through ${candidate.modality}.`;
      await rationale.click();
      await rationale.pressSequentially(review);
      await expect(rationale).toHaveValue(review);
      const evidence = card.getByRole("textbox", {
        name: "Evidence or receipt references",
        exact: true,
      });
      if ((await evidence.inputValue()).trim().length === 0) {
        await evidence.click();
        await evidence.pressSequentially(`evidence-${candidate.experimentId}`);
      }
      if (candidate.action === "start_canary") {
        const maximumMissions = card.getByRole("spinbutton", {
          name: "Maximum missions",
          exact: true,
        });
        await maximumMissions.selectText();
        await maximumMissions.pressSequentially("1");
        const maximumMinutes = card.getByRole("spinbutton", {
          name: "Maximum minutes",
          exact: true,
        });
        await maximumMinutes.selectText();
        await maximumMinutes.pressSequentially("15");
      }
      if (candidate.action === "rollback") {
        await card.getByRole("radio", {
          name: new RegExp(fixture.priorStrategyId, "u"),
        }).check();
      }
      const label = PROMOTION_ACTION_LABELS[candidate.action];
      const button = card.getByRole("button", { name: label, exact: true });
      // Controlled form updates and a prior candidate's authoritative cache
      // reconciliation can land in the same frame on WebKit. Wait for the
      // product's real enabled state before arming the response observer; a
      // press against a still-disabled control is not an activation and must
      // never be mistaken for a backend timeout.
      await expect(button).toBeEnabled();
      const responsePromise = page.waitForResponse((response) =>
        new URL(response.url()).pathname
          === `/api/v2/research/experiments/${encodeURIComponent(candidate.experimentId)}/promotion`
        && response.request().method() === "POST");
      await interactionActivation.activate({
        manifestEntryId: "research.promotion-actions",
        controlId: "research-promotion-actions",
        option: label,
        materialState: PROMOTION_ACTION_MATERIAL_STATE,
        modality: candidate.modality,
        testId: TEST_IDS.promotionActions,
      }, () => candidate.modality === "pointer"
        ? button.click()
        : button.press("Enter"));
      const response = await responsePromise;
      expect(response.status(), await response.text()).toBe(200);
      expect(response.request().headers()["idempotency-key"]).toMatch(
        /^research-promotion-[0-9a-f-]+$/u,
      );
      expect(response.request().postDataJSON()).toMatchObject({
        action: candidate.action,
      });
      const body = await response.json() as {
        readonly lifecycle?: { readonly state?: string };
      };
      const canonicalState = body.lifecycle?.state;
      expect(canonicalState).toBeTruthy();
      await expect(card.getByText(canonicalState!, {
        exact: true,
      }).first()).toBeVisible();
      // A successful response is not sufficient product truth. The refreshed
      // lifecycle must remove the action that was just consumed before the
      // operator can begin reviewing another candidate. This also prevents an
      // unrelated card's in-progress form state from racing the authoritative
      // cache reconciliation on WebKit.
      await expect(button).toBeHidden();
    }
  } finally {
    if (fixture) completeResearchPromotionLifecycleFixture(fixture);
  }
});

test(`${TEST_IDS.promotionReliability} preserves retry intent, reconciles conflicts, and rejects skipped stages and unsafe canary bounds`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(240_000);
  let fixture: ResearchPromotionReliabilityFixture | undefined;
  let databaseLock: ReturnType<typeof holdResearchLabWriteLock> | undefined;
  const cardFor = (strategyId: string) => page
    .locator(".os-research-promotions > .os-card")
    .filter({
      has: page.getByRole("heading", {
        name: `Strategy ${strategyId}`,
        exact: true,
      }),
    });
  const fillCard = async (strategyId: string, rationale: string) => {
    const card = cardFor(strategyId);
    await expect(card).toHaveCount(1);
    await expect(card).toBeAttached();
    const rationaleInput = card.getByRole("textbox", {
      name: "Decision rationale",
      exact: true,
    });
    await expect(rationaleInput).toHaveCount(1);
    await expect(rationaleInput).toBeVisible();
    await rationaleInput.fill(rationale);
    await expect(rationaleInput).toHaveValue(rationale);
    await expect(card).toBeAttached();
    const evidence = card.getByRole("textbox", {
      name: "Evidence or receipt references",
      exact: true,
    });
    await expect(evidence).toHaveCount(1);
    await expect(evidence).toBeVisible();
    if ((await evidence.inputValue({ timeout: 7_500 })).trim().length === 0) {
      await evidence.fill(`evidence-${strategyId}`);
    }
    return card;
  };
  const reloadResearch = async (): Promise<void> => {
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.reload({ waitUntil: "domcontentloaded" }),
    );
  };
  try {
    fixture = seedResearchPromotionReliabilityFixture();
    await page.goto("/learning?view=research", {
      waitUntil: "domcontentloaded",
    });

    const retryCard = await fillCard(
      fixture.retryCandidate.strategyId,
      "Retry the exact reviewed holdout decision after local store pressure.",
    );
    const retryPath =
      `/api/v2/research/experiments/${encodeURIComponent(fixture.retryCandidate.experimentId)}/promotion`;
    databaseLock = holdResearchLabWriteLock();
    browserAudit.expectHttpResponse(page, {
      id: "research-promotion.store-busy",
      transport: "browser",
      method: "POST",
      pathname: retryPath,
      query: {},
      status: 503,
      occurrences: 4,
      reason: "Prove reload restoration, explicit discard, a fresh reviewed submission, and both physical retry modalities preserve the correct frozen mutation intent under real SQLite pressure.",
    });
    const initialFailure = page.waitForResponse((response) =>
      new URL(response.url()).pathname === retryPath
      && response.request().method() === "POST"
      && response.status() === 503);
    await retryCard.getByRole("button", {
      name: "Approve for isolated shadow",
      exact: true,
    }).click();
    const failed = await initialFailure;
    const discardedKey = failed.request().headers()["idempotency-key"];
    const discardedBody = failed.request().postDataJSON();
    expect(await failed.json()).toMatchObject({
      error: {
        code: "research_store_busy",
        retryable: true,
      },
    });
    databaseLock.release();
    databaseLock = undefined;
    await reloadResearch();
    const restoredCard = cardFor(fixture.retryCandidate.strategyId);
    await expect(restoredCard.getByRole("button", {
      name: "Try again",
      exact: true,
    })).toBeVisible();
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-discard-retained-decision",
      controlId: "research-promotion-discard-retained-decision",
      option: "Discard the retained decision before reviewing a new one",
      materialState: PROMOTION_RETAINED_DECISION_MATERIAL_STATE,
      modality: "pointer",
      testId: TEST_IDS.promotionReliability,
    }, () => restoredCard.getByRole("button", {
      name: "Discard retained decision",
      exact: true,
    }).click());
    await expect(restoredCard.getByRole("button", {
      name: "Try again",
      exact: true,
    })).toHaveCount(0);
    expect(await page.evaluate(() => Object.keys(sessionStorage).some((key) =>
      key.startsWith("ti-scale.research.promotion-intent.v1.")))).toBe(false);

    const freshCard = await fillCard(
      fixture.retryCandidate.strategyId,
      "Submit a newly reviewed decision after deliberately discarding the restored retry record.",
    );
    const freshFailure = page.waitForResponse((response) =>
      new URL(response.url()).pathname === retryPath
      && response.request().method() === "POST"
      && response.status() === 503);
    databaseLock = holdResearchLabWriteLock();
    await freshCard.getByRole("button", {
      name: "Approve for isolated shadow",
      exact: true,
    }).click();
    const newlyFailed = await freshFailure;
    const frozenKey = newlyFailed.request().headers()["idempotency-key"];
    const frozenBody = newlyFailed.request().postDataJSON();
    expect(frozenKey).not.toBe(discardedKey);
    expect(frozenBody).not.toEqual(discardedBody);

    databaseLock.release();
    databaseLock = undefined;
    await reloadResearch();
    await expect(cardFor(fixture.retryCandidate.strategyId).getByRole(
      "button",
      { name: "Try again", exact: true },
    )).toBeVisible();
    for (const modality of ["pointer", "keyboard"] as const) {
      databaseLock = holdResearchLabWriteLock();
      const retryResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === retryPath
        && response.request().method() === "POST"
        && response.status() === 503);
      const retry = retryCard.getByRole("button", {
        name: "Try again",
        exact: true,
      });
      await interactionActivation.activate({
        manifestEntryId: "research.promotion-mutation-retry",
        controlId: "research-promotion-mutation-retry",
        option: "Retry the exact promotion intent with its original idempotency key",
        materialState: "A real SQLite write reservation returned retryable research_store_busy for a human promotion transition",
        modality,
        testId: TEST_IDS.promotionReliability,
      }, () => modality === "pointer" ? retry.click() : retry.press("Enter"));
      const response = await retryResponse;
      expect(response.request().headers()["idempotency-key"]).toBe(frozenKey);
      expect(response.request().postDataJSON()).toEqual(frozenBody);
      databaseLock.release();
      databaseLock = undefined;
    }
    const successfulRetry = page.waitForResponse((response) =>
      new URL(response.url()).pathname === retryPath
      && response.request().method() === "POST"
      && response.status() === 200);
    await retryCard.getByRole("button", {
      name: "Try again",
      exact: true,
    }).click();
    expect((await successfulRetry).request().headers()["idempotency-key"])
      .toBe(frozenKey);

    for (const candidate of fixture.conflictCandidates) {
      await reloadResearch();
      const card = await fillCard(
        candidate.strategyId,
        "Reconcile the current lifecycle before making a new decision.",
      );
      advanceResearchPromotionHumanDecision(
        candidate.experimentId,
        "approve_human_review",
      );
      const conflictPath =
        `/api/v2/research/experiments/${encodeURIComponent(candidate.experimentId)}/promotion`;
      browserAudit.expectHttpResponse(page, {
        id: `research-promotion.version-conflict.${candidate.modality}`,
        transport: "browser",
        method: "POST",
        pathname: conflictPath,
        query: {},
        status: 409,
        occurrences: 1,
        reason: "Prove a stale represented lifecycle version cannot overwrite a newer canonical decision.",
      });
      const conflict = page.waitForResponse((response) =>
        new URL(response.url()).pathname === conflictPath
        && response.request().method() === "POST"
        && response.status() === 409);
      await card.getByRole("button", {
        name: "Approve for isolated shadow",
        exact: true,
      }).click();
      expect(await (await conflict).json()).toMatchObject({
        error: {
          code: "research_promotion_version_conflict",
          retryable: false,
        },
      });
      const refreshResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/api/v2/research"
        && response.request().method() === "GET"
        && response.status() === 200);
      const refresh = card.getByRole("button", {
        name: "Refresh lifecycle state",
        exact: true,
      });
      await interactionActivation.activate({
        manifestEntryId: "research.promotion-refresh",
        controlId: "research-promotion-refresh",
        option: "Refresh the current lifecycle without replaying the stale mutation",
        materialState: "A non-retryable lifecycle-version conflict is represented",
        modality: candidate.modality,
        testId: TEST_IDS.promotionReliability,
      }, () => candidate.modality === "pointer"
        ? refresh.click()
        : refresh.press("Enter"));
      await refreshResponse;
    }

    const skipped = readResearchPromotionCandidateVersion(
      fixture.skippedStageCandidate.experimentId,
    );
    const directMutationCsrf = (await page.context().cookies())
      .find(({ name }) => name === "ti_scale_csrf")?.value;
    expect(
      directMutationCsrf,
      "The authenticated Research Lab browser context must carry its CSRF proof",
    ).toBeTruthy();
    const skippedPath =
      `/api/v2/research/experiments/${encodeURIComponent(fixture.skippedStageCandidate.experimentId)}/promotion`;
    const expectedSkippedStage = browserAudit.expectHttpResponse(page, {
      id: "research.promotion.reject-skipped-stage",
      transport: "api-request",
      method: "POST",
      pathname: skippedPath,
      query: {},
      status: 409,
      occurrences: 1,
      reason: "Prove a candidate cannot bypass the required promotion lifecycle stages.",
    });
    const skippedResponse = await browserAudit.request(page.request, {
      method: "POST",
      url: skippedPath,
      expectedResponseId: expectedSkippedStage,
      options: {
        headers: {
          "Idempotency-Key": `research-skipped-${crypto.randomUUID()}`,
          "X-Ti-Scale-CSRF": directMutationCsrf!,
        },
        data: {
          expectedVersion: skipped.version,
          action: "start_shadow",
          rationale: "Attempting to skip policy, benchmark, holdout, and human review.",
          evidenceRefs: ["negative-skipped-stage"],
        },
      },
    });
    expect(skippedResponse.status()).toBe(409);
    expect(await skippedResponse.json()).toMatchObject({
      error: { code: "research_promotion_action_unavailable" },
    });

    await reloadResearch();
    const invalidCanaryCard = await fillCard(
      fixture.invalidCanaryCandidate.strategyId,
      "Reject a canary that has no valid mission bound.",
    );
    await invalidCanaryCard.getByRole("spinbutton", {
      name: "Maximum missions",
      exact: true,
    }).fill("0");
    await expect(invalidCanaryCard.getByRole("button", {
      name: "Start bounded canary",
      exact: true,
    })).toBeDisabled();
    const invalidCanary = readResearchPromotionCandidateVersion(
      fixture.invalidCanaryCandidate.experimentId,
    );
    const invalidCanaryPath =
      `/api/v2/research/experiments/${encodeURIComponent(fixture.invalidCanaryCandidate.experimentId)}/promotion`;
    const expectedInvalidCanary = browserAudit.expectHttpResponse(page, {
      id: "research.promotion.reject-invalid-canary-bounds",
      transport: "api-request",
      method: "POST",
      pathname: invalidCanaryPath,
      query: {},
      status: 400,
      occurrences: 1,
      reason: "Prove a canary cannot start without a positive bounded mission count.",
    });
    const invalidCanaryResponse = await browserAudit.request(page.request, {
      method: "POST",
      url: invalidCanaryPath,
      expectedResponseId: expectedInvalidCanary,
      options: {
        headers: {
          "Idempotency-Key": `research-canary-invalid-${crypto.randomUUID()}`,
          "X-Ti-Scale-CSRF": directMutationCsrf!,
        },
        data: {
          expectedVersion: invalidCanary.version,
          action: "start_canary",
          rationale: "A zero-mission canary must be rejected.",
          evidenceRefs: ["negative-canary-bounds"],
          canaryBounds: {
            maxMissions: 0,
            maxWallClockMs: 60_000,
          },
        },
      },
    });
    expect(invalidCanaryResponse.status()).toBe(400);
    expect(await invalidCanaryResponse.json()).toMatchObject({
      error: { code: "invalid_research_request" },
    });
  } finally {
    databaseLock?.release();
    if (fixture) completeResearchPromotionLifecycleFixture(fixture);
  }
});

test(`${TEST_IDS.promotionResponseLoss} distinguishes committed, unchanged, and different-reviewer outcomes after an unusable response`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(240_000);
  let fixture: ResearchPromotionReliabilityFixture | undefined;
  const cardFor = (strategyId: string) => page
    .locator(".os-research-promotions > .os-card")
    .filter({
      has: page.getByRole("heading", {
        name: `Strategy ${strategyId}`,
        exact: true,
      }),
    });
  const fillCard = async (strategyId: string, rationale: string) => {
    const card = cardFor(strategyId);
    await card.getByRole("textbox", {
      name: "Decision rationale",
      exact: true,
    }).fill(rationale);
    const evidence = card.getByRole("textbox", {
      name: "Evidence or receipt references",
      exact: true,
    });
    if ((await evidence.inputValue()).trim().length === 0) {
      await evidence.fill(`evidence-${strategyId}`);
    }
    return card;
  };
  const reloadResearch = async (): Promise<void> => {
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.reload({ waitUntil: "domcontentloaded" }),
    );
  };
  const malformedLifecycle = JSON.stringify({
    schemaVersion: "2.4",
    lifecycle: null,
  });
  try {
    fixture = seedResearchPromotionReliabilityFixture();
    await page.goto("/learning?view=research", {
      waitUntil: "domcontentloaded",
    });

    const applied = fixture.responseLossAppliedCandidate;
    const appliedPath =
      `/api/v2/research/experiments/${encodeURIComponent(applied.experimentId)}/promotion`;
    const appliedCard = await fillCard(
      applied.strategyId,
      "Approve the signed holdout while proving a committed response can be reconciled.",
    );
    await page.route(`**${appliedPath}`, async (route) => {
      const upstream = await route.fetch();
      expect(upstream.status(), await upstream.text()).toBe(200);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: malformedLifecycle,
      });
    }, { times: 1 });
    await appliedCard.getByRole("button", {
      name: "Approve for isolated shadow",
      exact: true,
    }).click();
    const appliedRefresh = appliedCard.getByRole("button", {
      name: "Refresh lifecycle state",
      exact: true,
    });
    await expect(appliedRefresh).toBeFocused();
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-uncertain-refresh",
      controlId: "research-promotion-uncertain-refresh",
      option: "Refresh canonical lifecycle after an unusable mutation response",
      materialState: "A promotion response was unusable and the original decision outcome is uncertain",
      modality: "pointer",
      testId: TEST_IDS.promotionResponseLoss,
    }, () => appliedRefresh.click());
    await expect(appliedCard.getByText(
      "Canonical lifecycle state confirms the earlier Research decision was recorded under your reviewer identity.",
      { exact: true },
    )).toBeVisible();
    await expect(appliedCard.getByRole("textbox", {
      name: "Decision rationale",
      exact: true,
    })).toBeFocused();
    expect(await page.evaluate(() => Object.keys(sessionStorage).some((key) =>
      key.startsWith("ti-scale.research.promotion-intent.v1.")))).toBe(false);

    const unchanged = fixture.responseLossUnchangedCandidate;
    const unchangedPath =
      `/api/v2/research/experiments/${encodeURIComponent(unchanged.experimentId)}/promotion`;
    let firstFrozenBody = "";
    let firstFrozenKey = "";
    const unchangedCard = await fillCard(
      unchanged.strategyId,
      "Retain this exact decision when the response is unusable and canonical state is unchanged.",
    );
    await page.route(`**${unchangedPath}`, async (route) => {
      firstFrozenBody = route.request().postData() ?? "";
      firstFrozenKey = route.request().headers()["idempotency-key"] ?? "";
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: malformedLifecycle,
      });
    }, { times: 1 });
    await unchangedCard.getByRole("button", {
      name: "Approve for isolated shadow",
      exact: true,
    }).click();
    await expect(unchangedCard.getByRole("button", {
      name: "Refresh lifecycle state",
      exact: true,
    })).toBeFocused();
    await reloadResearch();
    const restoredUnchanged = cardFor(unchanged.strategyId);
    await expect(restoredUnchanged.getByRole("button", {
      name: "Try again",
      exact: true,
    })).toBeVisible();
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-discard-retained-decision",
      controlId: "research-promotion-discard-retained-decision",
      option: "Discard the retained decision before reviewing a new one",
      materialState: PROMOTION_RETAINED_DECISION_MATERIAL_STATE,
      modality: "keyboard",
      testId: TEST_IDS.promotionResponseLoss,
    }, () => restoredUnchanged.getByRole("button", {
      name: "Discard retained decision",
      exact: true,
    }).press("Enter"));
    await expect(restoredUnchanged.getByRole("textbox", {
      name: "Decision rationale",
      exact: true,
    })).toBeFocused();

    let replayBody = "";
    let replayKey = "";
    await fillCard(
      unchanged.strategyId,
      "Replay these exact represented bytes only after reload confirms state is unchanged.",
    );
    await page.route(`**${unchangedPath}`, async (route) => {
      replayBody = route.request().postData() ?? "";
      replayKey = route.request().headers()["idempotency-key"] ?? "";
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: malformedLifecycle,
      });
    }, { times: 1 });
    await restoredUnchanged.getByRole("button", {
      name: "Approve for isolated shadow",
      exact: true,
    }).click();
    // Do not navigate merely because the routed response was fulfilled. The
    // client must finish parsing the unusable payload, persist the exact
    // retained decision, and expose its reconciliation control first.
    await expect(restoredUnchanged.getByRole("button", {
      name: "Refresh lifecycle state",
      exact: true,
    })).toBeFocused();
    await reloadResearch();
    const retryCard = cardFor(unchanged.strategyId);
    const replayResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === unchangedPath
      && response.request().method() === "POST"
      && response.status() === 200);
    await retryCard.getByRole("button", {
      name: "Try again",
      exact: true,
    }).click();
    const acceptedReplay = await replayResponse;
    expect(acceptedReplay.request().postData()).toBe(replayBody);
    expect(acceptedReplay.request().headers()["idempotency-key"]).toBe(replayKey);
    expect(replayBody).not.toBe(firstFrozenBody);
    expect(replayKey).not.toBe(firstFrozenKey);

    const different = fixture.differentReviewerCandidate;
    const differentPath =
      `/api/v2/research/experiments/${encodeURIComponent(different.experimentId)}/promotion`;
    const differentCard = await fillCard(
      different.strategyId,
      "Keep reviewer attribution exact when another authorized reviewer acts first.",
    );
    await page.route(`**${differentPath}`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: malformedLifecycle,
      });
    }, { times: 1 });
    await differentCard.getByRole("button", {
      name: "Approve for isolated shadow",
      exact: true,
    }).click();
    advanceResearchPromotionHumanDecision(
      different.experimentId,
      "approve_human_review",
      "e2e-different-authorized-reviewer",
    );
    const differentRefresh = differentCard.getByRole("button", {
      name: "Refresh lifecycle state",
      exact: true,
    });
    await interactionActivation.activate({
      manifestEntryId: "research.promotion-uncertain-refresh",
      controlId: "research-promotion-uncertain-refresh",
      option: "Refresh canonical lifecycle after an unusable mutation response",
      materialState: "A promotion response was unusable and the original decision outcome is uncertain",
      modality: "keyboard",
      testId: TEST_IDS.promotionResponseLoss,
    }, () => differentRefresh.press("Enter"));
    await expect(differentCard.getByText(
      "A different authorized reviewer recorded the same lifecycle action. Your retained decision was not recorded under your identity; review the canonical transition.",
      { exact: true },
    )).toBeVisible();
    await expect(differentCard.getByRole("button", {
      name: "Try again",
      exact: true,
    })).toHaveCount(0);
    await expect(differentCard.getByRole("textbox", {
      name: "Decision rationale",
      exact: true,
    })).toBeFocused();
    expect(await page.evaluate(() => Object.keys(sessionStorage).some((key) =>
      key.startsWith("ti-scale.research.promotion-intent.v1.")))).toBe(false);
  } finally {
    if (fixture) completeResearchPromotionLifecycleFixture(fixture);
  }
});

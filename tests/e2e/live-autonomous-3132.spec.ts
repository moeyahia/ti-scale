import {
  DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST,
  startDisposableAutonomousAssessmentTarget,
} from "../../server/autonomous-runtime/testing/DisposableAutonomousAssessmentTarget";
import type { AutonomousMissionPreflight } from "../../src/domain/types/commandOs";
import type {
  RunMetricsSnapshotList,
} from "../../src/domain/types/runIntelligence";
import {
  AUTONOMOUS_INTAKE_ROUTE,
  advanceAutonomousIntake,
  autonomousIntakeGroup,
  autonomousTitaniumSelect,
  chooseAutonomousTitaniumOption,
} from "./support/autonomousIntake";
import type { BrowserAuditController } from "./support/browserAudit";
import {
  expect,
  test,
  type APIResponse,
  type Page,
  type Response,
} from "./support/playwright";

const RUN_TIMEOUT_MS = 15 * 60_000;
const POLL_INTERVAL_MS = 750;
const LIVE_TEMPLATE_ID = "external_web_assessment";
const TERMINAL_FAILURES = new Set([
  "blocked",
  "cancelled",
  "failed",
  "waiting_guided_decision",
]);

interface CreatedMission {
  readonly mission: {
    readonly id: string;
    readonly title: string;
    readonly journey: "autonomous";
  };
  readonly run: {
    readonly id: string;
    readonly status: string;
    readonly journey: "autonomous";
  };
  readonly nextUrl: string;
}

interface RunResponse {
  readonly schemaVersion: "2.4";
  readonly run: {
    readonly id: string;
    readonly missionId: string;
    readonly journey: "autonomous";
    readonly status: string;
    readonly statusReason: string | null;
    readonly progress: number;
  };
}

interface PageResult<T> {
  readonly items: readonly T[];
  readonly nextCursor: string | null;
}

interface EvidenceItem {
  readonly id: string;
  readonly runId: string | null;
  readonly verificationState: string;
  readonly contentHash: string;
  readonly summary: string;
}

interface ReportItem {
  readonly id: string;
  readonly runId: string | null;
  readonly artifactType: string;
  readonly contentHash: string;
  readonly mission: {
    readonly id: string;
    readonly name: string;
  };
}

interface ContextPackItem {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string | null;
  readonly journey: "autonomous" | "guided";
  readonly purpose: string;
  readonly retrievedItemCount: number;
  readonly usedItemCount: number;
}

interface VaultSnapshot {
  readonly enabled: boolean;
  readonly connections: readonly {
    readonly id: string;
    readonly displayName: string;
    readonly vaultPath: string;
    readonly status: string;
    readonly pathAvailable?: boolean;
    readonly trackedNoteCount?: number;
    readonly healthChecks?: {
      readonly read?: boolean;
      readonly write?: boolean;
      readonly rename?: boolean;
      readonly delete?: boolean;
    };
  }[];
  readonly syncStates: readonly {
    readonly connectionId: string;
    readonly nodeId: string | null;
    readonly status: string;
  }[];
}

async function readJson<T>(
  page: Page,
  browserAudit: BrowserAuditController,
  pathname: string,
): Promise<T> {
  const response = await browserAudit.request(page.request, {
    method: "GET",
    url: pathname,
    options: { headers: { Accept: "application/json" } },
  });
  expect(response.status(), `Live endpoint must resolve: ${pathname}`).toBe(200);
  return response.json() as Promise<T>;
}

async function navigate(
  page: Page,
  browserAudit: BrowserAuditController,
  pathname: string,
): Promise<void> {
  const response = await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.goto(pathname, { waitUntil: "domcontentloaded" }),
  );
  expect(response?.status(), `Live document must resolve: ${pathname}`).toBe(200);
}

async function waitForCompletedRun(
  page: Page,
  browserAudit: BrowserAuditController,
  runId: string,
): Promise<RunResponse["run"]> {
  const deadline = Date.now() + RUN_TIMEOUT_MS;
  let latest: RunResponse["run"] | undefined;
  while (Date.now() < deadline) {
    const response = await readJson<RunResponse>(
      page,
      browserAudit,
      `/api/v2/runs/${encodeURIComponent(runId)}`,
    );
    latest = response.run;
    if (latest.status === "completed") return latest;
    if (TERMINAL_FAILURES.has(latest.status)) {
      throw new Error(
        `Live Autonomous run entered ${latest.status}: ${latest.statusReason ?? "No diagnosis returned"}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  throw new Error(
    `Live Autonomous run did not complete within ${RUN_TIMEOUT_MS} ms; latest state was ${latest?.status ?? "unknown"}: ${latest?.statusReason ?? "no reason"}`,
  );
}

async function launchFromRecommendedDefaults(
  page: Page,
): Promise<{
  readonly created: CreatedMission;
  readonly preflight: AutonomousMissionPreflight;
  readonly createResponse: APIResponse | Response;
}> {
  await page.goto(AUTONOMOUS_INTAKE_ROUTE, { waitUntil: "domcontentloaded" });
  await expect(
    autonomousIntakeGroup(page, "Authorization and exact scope"),
  ).toBeVisible();

  await chooseAutonomousTitaniumOption(
    autonomousTitaniumSelect(page, /Mission template/u),
    LIVE_TEMPLATE_ID,
    "pointer",
  );
  await chooseAutonomousTitaniumOption(
    autonomousTitaniumSelect(page, /Environment classification/u),
    "local_disposable_lab",
    "pointer",
  );
  await page
    .getByLabel("Authorized targets or environment references", {
      exact: false,
    })
    .fill(DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST);
  await page
    .getByRole("checkbox", {
      name: /I confirm these targets and the selected action policy are authorized/u,
    })
    .check();

  await advanceAutonomousIntake(page, "Outcome and collaboration");
  await expect(page.getByLabel("Mission title", { exact: false })).toHaveValue("");
  await expect(
    page.getByLabel("Authorized objective", { exact: false }),
  ).toHaveValue("");

  await advanceAutonomousIntake(page, "Autonomous operating contract");
  const contract = autonomousIntakeGroup(
    page,
    "Autonomous operating contract",
  );
  await expect(
    contract.getByRole("region", { name: "Operating contract checklists" }),
  ).toContainText("Four registry-backed checklists");
  await expect(
    contract.getByRole("button", {
      name: "Use recommended defaults",
      exact: true,
    }),
  ).toBeDisabled();

  const teamAdvance = await advanceAutonomousIntake(
    page,
    "Specialist team and execution readiness",
    { expectPreflight: true },
  );
  if (!teamAdvance.preflight) {
    throw new Error("The live Team step did not return a preflight");
  }
  const initialPreflight =
    await teamAdvance.preflight.json() as AutonomousMissionPreflight;
  expect(initialPreflight.readiness.status).toBe("ready");
  expect(
    initialPreflight.readiness.checks.filter(({ status }) => status === "fail"),
  ).toEqual([]);

  const team = autonomousIntakeGroup(
    page,
    "Specialist team and execution readiness",
  );
  await expect(
    team.getByRole("heading", { name: "ReconScout", exact: true }),
  ).toBeVisible();
  await expect(
    team.getByRole("heading", { name: "WebBreaker", exact: true }),
  ).toBeVisible();
  await expect(
    team.getByRole("heading", { name: "VulnIntel", exact: true }),
  ).toBeVisible();
  await expect(team.locator('input[type="checkbox"]:checked')).toHaveCount(3);

  await advanceAutonomousIntake(page, "Second Brain context", {
    expectPreflight: true,
  });
  const context = autonomousIntakeGroup(page, "Second Brain context");
  for (const label of [
    "Confirmed operator preferences",
    "Verified operational lessons",
    "Confirmed historical attack knowledge",
    "Verified attack safety knowledge",
  ]) {
    await expect(
      context.getByRole("checkbox", { name: new RegExp(label, "u") }),
    ).toBeChecked();
  }

  const reviewAdvance = await advanceAutonomousIntake(
    page,
    "Review the resolved mission",
    { expectPreflight: true },
  );
  if (!reviewAdvance.preflight) {
    throw new Error("The live Review step did not return a preflight");
  }
  const preflight =
    await reviewAdvance.preflight.json() as AutonomousMissionPreflight;
  expect(preflight.readiness.status).toBe("ready");
  expect(
    preflight.readiness.checks.filter(({ status }) => status === "fail"),
  ).toEqual([]);

  const review = autonomousIntakeGroup(page, "Review the resolved mission");
  await expect(
    review.getByRole("region", {
      name: "Resolved operating contract checklist",
    }),
  ).toBeVisible();
  await expect(review.getByText("Recommended default", { exact: true }))
    .toHaveCount(5);
  await expect(review.getByText("Always enforced", { exact: true }))
    .toHaveCount(1);
  await expect(review).toContainText("Autonomous Assessment");

  const launch = page.getByRole("button", {
    name: "Launch Autonomous Assessment",
    exact: true,
  });
  await expect(launch).toBeEnabled();
  const createResponsePromise = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === "/api/v2/missions"
      && response.request().method() === "POST",
  );
  await launch.click();
  const createResponse = await createResponsePromise;
  expect(
    createResponse.status(),
    await createResponse.text(),
  ).toBe(201);
  const created = await createResponse.json() as CreatedMission;
  expect(created.mission.journey).toBe("autonomous");
  expect(created.run.journey).toBe("autonomous");
  expect(created.nextUrl).toBe(`/missions/${created.mission.id}`);
  await expect.poll(() => new URL(page.url()).pathname).toBe(created.nextUrl);
  return { created, preflight, createResponse };
}

test(
  "launches and completes a real authenticated Autonomous assessment through the live UI, evidence, reports, Brain, and Vault",
  async ({ page, browserAudit }, testInfo) => {
    test.setTimeout(20 * 60_000);
    await page.emulateMedia({ reducedMotion: "reduce" });
    const target = await startDisposableAutonomousAssessmentTarget();

    try {
      const { created, preflight } =
        await launchFromRecommendedDefaults(page);
      expect(preflight.outcome.id).toBe("assessment");

      await page.getByRole("button", { name: "Live", exact: true }).click();
      await expect(page.locator('[data-mission-tab="live"]')).toBeVisible();
      await expect(
        page.getByRole("region", { name: "Selected run status" }),
      ).toBeVisible();
      await expect(
        page.getByRole("heading", {
          name: "Plan and agent ownership",
          exact: true,
        }),
      ).toBeVisible();

      const terminal = await waitForCompletedRun(
        page,
        browserAudit,
        created.run.id,
      );
      expect(terminal.progress).toBe(1);
      expect(target.requests().length).toBeGreaterThan(0);
      expect(
        target.requests().some(({ method }) =>
          ["GET", "HEAD"].includes(method)),
      ).toBe(true);
      expect(
        target.requests().every(({ outcome }) => outcome === "served"),
      ).toBe(true);

      await page.getByRole("button", { name: "Summary", exact: true }).click();
      await expect(page.locator('[data-mission-tab="summary"]')).toBeVisible();
      await expect(
        page.getByRole("region", { name: "Selected run status" }),
      ).toContainText("Completed autonomously");
      const completionReview = page.getByRole("region", {
        name: "Completed autonomously",
        exact: true,
      });
      await expect(completionReview).toBeVisible();
      await expect(completionReview).toContainText("Mission completion review");
      await expect(
        page.getByRole("heading", {
          name: "Recomputed run intelligence",
          exact: true,
        }),
      ).toBeVisible();

      const metricSnapshots = await readJson<RunMetricsSnapshotList>(
        page,
        browserAudit,
        `/api/v2/runs/${encodeURIComponent(created.run.id)}/intelligence/metrics/snapshots`,
      );
      expect(metricSnapshots.items).toHaveLength(1);
      expect(metricSnapshots.latestSnapshotId)
        .toBe(metricSnapshots.items[0]!.id);
      expect(metricSnapshots.items[0]).toMatchObject({
        runId: created.run.id,
        missionId: created.mission.id,
        metricSchemaVersion: "run-metrics-v2.4.0",
      });
      expect(metricSnapshots.items[0]!.recomputationHash)
        .toMatch(/^[a-f0-9]{64}$/u);
      await expect(
        page.getByRole("heading", {
          name: "No reproducible metrics snapshot",
          exact: true,
        }),
      ).toHaveCount(0);

      const decisions = await readJson<PageResult<{ readonly id: string }>>(
        page,
        browserAudit,
        `/api/v2/decisions?runId=${encodeURIComponent(created.run.id)}&limit=100`,
      );
      expect(decisions.items).toEqual([]);

      const evidence = await readJson<PageResult<EvidenceItem>>(
        page,
        browserAudit,
        `/api/v2/intelligence/evidence?missionId=${encodeURIComponent(created.mission.id)}&runId=${encodeURIComponent(created.run.id)}&limit=100`,
      );
      const runEvidence = evidence.items.filter(
        ({ runId }) => runId === created.run.id,
      );
      expect(runEvidence.length).toBeGreaterThan(0);
      expect(
        runEvidence.every(
          ({ verificationState, contentHash }) =>
            verificationState === "verified"
            && /^[a-f0-9]{64}$/u.test(contentHash),
        ),
      ).toBe(true);

      await page.getByRole("button", { name: "Evidence", exact: true }).click();
      await expect(page.locator('[data-mission-tab="evidence"]')).toBeVisible();
      await expect(
        page.getByRole("heading", {
          name: "From technical record to verified support",
          exact: true,
        }),
      ).toBeVisible();
      await page.getByRole("tab", {
        name: "Verified evidence",
        exact: true,
      }).click();
      await expect(
        page.getByRole("table").filter({ hasText: "Verified evidence" }),
      ).toBeVisible();
      await expect(page.getByRole("heading", {
        name: runEvidence[0]!.summary,
        exact: true,
      })).toBeVisible();

      const reports = await readJson<PageResult<ReportItem>>(
        page,
        browserAudit,
        `/api/v2/reports?missionId=${encodeURIComponent(created.mission.id)}&limit=100`,
      );
      const runReports = reports.items.filter(
        ({ runId }) => runId === created.run.id,
      );
      expect(runReports.length).toBeGreaterThan(0);
      expect(
        runReports.every(
          ({ contentHash, mission }) =>
            /^[a-f0-9]{64}$/u.test(contentHash)
            && mission.id === created.mission.id,
        ),
      ).toBe(true);

      await navigate(
        page,
        browserAudit,
        `/reports?missionId=${encodeURIComponent(created.mission.id)}`,
      );
      await expect(
        page.getByRole("heading", { level: 1, name: "Reports", exact: true }),
      ).toBeVisible();
      const reportLink = page.getByRole("link", {
        name: new RegExp(
          `^Open report ${runReports[0]!.artifactType.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")} \\(`,
          "u",
        ),
      }).first();
      await expect(reportLink).toBeVisible();
      await reportLink.click();
      await expect.poll(() => new URL(page.url()).pathname)
        .toBe(`/reports/${runReports[0]!.id}`);
      await expect(page.getByText(runReports[0]!.contentHash, { exact: true }))
        .toBeVisible();

      const contextPacks = await readJson<PageResult<ContextPackItem>>(
        page,
        browserAudit,
        `/api/v2/brain/context-packs?missionId=${encodeURIComponent(created.mission.id)}&limit=200`,
      );
      const runContexts = contextPacks.items.filter(
        ({ runId }) => runId === created.run.id,
      );
      expect(runContexts.length).toBeGreaterThan(0);
      expect(runContexts.some(({ purpose }) => /\bplan/iu.test(purpose)))
        .toBe(true);
      expect(runContexts.some(({ purpose }) => /\breport/iu.test(purpose)))
        .toBe(true);

      await navigate(page, browserAudit, `${created.nextUrl}?tab=brain`);
      await expect(page.locator('[data-mission-tab="brain"]')).toBeVisible();
      await expect(
        page.getByRole("heading", {
          name: "Context packs used",
          exact: true,
        }),
      ).toBeVisible();
      await expect(
        page.getByRole("button", {
          name: /Autonomous planning|planning/iu,
        }).first(),
      ).toBeVisible();

      const vault = await readJson<VaultSnapshot>(
        page,
        browserAudit,
        "/api/v2/brain/vault",
      );
      const activeVault = vault.connections.find(
        ({ displayName, vaultPath }) =>
          displayName === "Ti-Scale Attack Knowledge Vault"
          && vaultPath === "Attack-Knowledge-Vault",
      );
      expect(activeVault).toMatchObject({
        status: "connected",
        pathAvailable: true,
        healthChecks: {
          read: true,
          write: true,
          rename: true,
          delete: true,
        },
      });
      expect(activeVault?.trackedNoteCount ?? 0).toBeGreaterThan(0);
      expect(
        vault.syncStates.some(
          ({ connectionId, status }) =>
            connectionId === activeVault?.id && status === "synced",
        ),
      ).toBe(true);

      await navigate(page, browserAudit, "/brain/vault");
      await expect(
        page.getByRole("heading", {
          level: 1,
          name: "Obsidian Vault",
          exact: true,
        }),
      ).toBeVisible();
      const activeVaults = page.getByRole("region", {
        name: "Active Obsidian Vaults",
        exact: true,
      });
      await expect(activeVaults).toBeVisible();
      await expect(
        activeVaults.getByRole("heading", {
          name: "Attack-Knowledge-Vault",
          exact: true,
        }),
      ).toBeVisible();
      await expect(
        page.getByText("Attack Knowledge Vault is active", { exact: true }),
      ).toBeVisible();

      await testInfo.attach("live-autonomous-3132-receipt", {
        body: Buffer.from(JSON.stringify({
          schemaVersion: "ti-scale.live-autonomous-browser-proof.v1",
          checkedAt: new Date().toISOString(),
          missionId: created.mission.id,
          runId: created.run.id,
          terminalStatus: terminal.status,
          target: DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST,
          targetRequestCount: target.requests().length,
          targetMethods: [...new Set(
            target.requests().map(({ method }) => method),
          )].sort(),
          verifiedEvidenceCount: runEvidence.length,
          reportCount: runReports.length,
          contextPackCount: runContexts.length,
          runMetricsSnapshotId: metricSnapshots.items[0]!.id,
          activeVaultConnectionId: activeVault?.id,
          activeVaultTrackedNotes: activeVault?.trackedNoteCount,
          operatorTokenSerialized: false,
          mockApiUsed: false,
        }, null, 2)),
        contentType: "application/json",
      });
      await testInfo.attach("live-autonomous-vault", {
        body: await page.screenshot({
          fullPage: true,
          animations: "disabled",
        }),
        contentType: "image/png",
      });
    } finally {
      await browserAudit.closePageBeforeDependencyShutdown(page);
      await target.close();
    }
  },
);

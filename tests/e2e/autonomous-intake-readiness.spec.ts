import type {
  AutonomousMissionPreflight,
  ReadinessCheck,
} from "../../src/domain/types/commandOs";
import type { RuntimeReadinessSnapshot } from "../../src/domain/types/runtimeReadiness";
import {
  activateAutonomousIntake,
  advanceAutonomousIntake,
  autonomousIntakeGroup,
  autonomousTitaniumSelect,
  chooseAutonomousTitaniumOption,
  createIntakeRequestLedger,
  type IntakeReceiptContext,
} from "./support/autonomousIntake";
import { createMissionIntakeDynamicFixture } from "./support/missionIntakeDynamicFixture";
import {
  expect,
  test,
  type Locator,
  type Page,
  type Route,
} from "./support/playwright";

const TEST_ID = "e2e.autonomous-intake.readiness";
const BLOCKED_CHECKS: readonly ReadinessCheck[] = [
  ["execution_boundary_autonomous", "Autonomous execution boundary"],
  ["contract_action_boundary", "Executable action boundary"],
  ["provider_execution_autonomous", "Autonomous provider enforcement"],
  ["contract_provider_inventory", "Inspected enforcing provider paths"],
  ["contract_specialist_selection", "Signed specialist pool"],
  ["mcp_execution_autonomous", "Autonomous MCP execution"],
  ["contract_evidence_capability", "Required evidence capability"],
  ["provider_token_accounting_autonomous", "Exact token accounting"],
  ["provider_cost_accounting_autonomous", "Exact cost accounting"],
].map(([id, label]) => ({
  id,
  label,
  status: "fail" as const,
  journeys: ["autonomous" as const],
  impact: `${label} is not currently satisfied for unattended execution.`,
  remediation: `Repair ${label.toLocaleLowerCase("en-US")} and rerun preflight.`,
}));

type RuntimeState = "blocked" | "ready-a" | "ready-b";
type PreflightState = "blocked" | "degraded" | "ready" | "error";

function runtimeProjection(
  current: RuntimeReadinessSnapshot,
  state: RuntimeState,
): RuntimeReadinessSnapshot {
  const ready = state !== "blocked";
  return {
    ...current,
    status: ready ? "healthy" : "degraded",
    execution: {
      ...current.execution,
      autonomous: ready ? "ready" : "unavailable",
      actionBoundaryActive: ready,
      delegationEnforced: ready,
      noHandsCommanderEnforced: ready,
    },
    dependencies: {
      ...current.dependencies,
      providers: {
        ...current.dependencies.providers,
        status: ready ? "available" : "unavailable",
        initializing: false,
        probing: 0,
        reason: ready
          ? state === "ready-a"
            ? "Enforcing provider path is ready under capability generation A."
            : "Enforcing provider path is ready under capability generation B."
          : "The enforcing provider path has not finished its current attestation.",
        callable: ready ? Math.max(1, current.dependencies.providers.callable) : 0,
        enforcing: ready ? Math.max(1, current.dependencies.providers.enforcing) : 0,
      },
      mcp: {
        ...current.dependencies.mcp,
        status: ready ? "available" : "unavailable",
        initializing: false,
        probingServers: 0,
        reason: ready
          ? null
          : "No reviewed Autonomous MCP path is currently attested.",
        configuredServers: Math.max(1, current.dependencies.mcp.configuredServers),
        runnableServers: ready
          ? Math.max(1, current.dependencies.mcp.runnableServers)
          : 0,
        executionMode: ready ? "enabled" : "disabled",
      },
      secondBrain: {
        ...current.dependencies.secondBrain,
        status: "healthy",
        canonicalStoreAvailable: true,
        reason: null,
      },
    },
    checkedAt: new Date().toISOString(),
  };
}

function preflightProjection(
  current: AutonomousMissionPreflight,
  state: Exclude<PreflightState, "error">,
): AutonomousMissionPreflight {
  if (state === "blocked") {
    return {
      ...current,
      readiness: {
        status: "blocked",
        score: 51,
        checks: [...BLOCKED_CHECKS],
      },
    };
  }
  const sourceChecks = current.readiness.checks.length > 0
    ? current.readiness.checks
    : [{
        id: "contract_controls",
        label: "Signed contract controls",
        status: "pass" as const,
        journeys: ["autonomous" as const],
        impact: "The signed contract controls are current.",
      }];
  return {
    ...current,
    readiness: {
      status: state,
      score: state === "degraded" ? 92 : 100,
      checks: sourceChecks.map((check, index) => ({
        ...check,
        status: state === "degraded" && index === 0 ? "warn" : "pass",
        impact: state === "degraded" && index === 0
          ? "One non-blocking advisory remains visible for operator review."
          : check.impact,
        remediation: undefined,
      })),
    },
  };
}

async function installReadinessStateRoutes(
  page: Page,
  state: {
    runtime: RuntimeState;
    preflight: PreflightState;
    holdFirstPreflight: boolean;
    delayNextReadyPreflight: boolean;
    releaseFirstPreflight?: () => void;
  },
): Promise<void> {
  let releaseFirst: (() => void) | undefined;
  const firstGate = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  state.releaseFirstPreflight = releaseFirst;

  await page.route("**/api/v2/system/readiness", async (requestRoute) => {
    const response = await requestRoute.fetch();
    const body = await response.json() as RuntimeReadinessSnapshot;
    await requestRoute.fulfill({
      response,
      json: runtimeProjection(body, state.runtime),
    });
  });
  await page.route("**/api/v2/missions/autonomous/preflight", async (requestRoute: Route) => {
    if (state.holdFirstPreflight) {
      state.holdFirstPreflight = false;
      await firstGate;
    }
    if (state.preflight === "error") {
      await new Promise((resolve) => setTimeout(resolve, 750));
      await requestRoute.fulfill({
        status: 503,
        contentType: "application/json; charset=utf-8",
        body: JSON.stringify({
          error: {
            code: "autonomous_preflight_temporarily_unavailable",
            message: "Autonomous preflight is temporarily unavailable",
            humanMessage: "The replacement Autonomous readiness review could not be completed.",
            retryable: true,
            category: "dependency",
            remediation: "Return to the previous step and run the contract review again.",
            traceId: "trace-autonomous-readiness-refresh",
            timestamp: new Date().toISOString(),
          },
        }),
      });
      return;
    }
    if (state.preflight === "ready" && state.delayNextReadyPreflight) {
      state.delayNextReadyPreflight = false;
      await new Promise((resolve) => setTimeout(resolve, 750));
    }
    const response = await requestRoute.fetch();
    const body = await response.json() as AutonomousMissionPreflight;
    await requestRoute.fulfill({
      response,
      json: preflightProjection(body, state.preflight),
    });
  });
}

async function exerciseAuditDisclosure(
  details: Locator,
  receipts: IntakeReceiptContext,
): Promise<void> {
  const summary = details.locator(":scope > summary");
  for (const modality of ["pointer", "keyboard"] as const) {
    if ((await details.getAttribute("open")) !== null) {
      if (modality === "pointer") await summary.click();
      else {
        await summary.focus();
        await summary.press("Enter");
      }
      await expect(details).not.toHaveAttribute("open", "");
    }
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.readiness.audit-checks",
      "Open current passed and advisory checks",
      modality,
      async () => {
        if (modality === "pointer") await summary.click();
        else {
          await summary.focus();
          await summary.press("Enter");
        }
        await expect(details).toHaveAttribute("open", "");
        await expect(details.getByRole("listitem")).not.toHaveCount(0);
      },
    );
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.readiness.audit-checks",
      "Close current passed and advisory checks",
      modality,
      async () => {
        if (modality === "pointer") await summary.click();
        else {
          await summary.focus();
          await summary.press("Enter");
        }
        await expect(details).not.toHaveAttribute("open", "");
      },
    );
  }
}

async function expectReviewGeometryFitsViewport(page: Page): Promise<void> {
  const geometry = await page.evaluate(async () => {
    const back = [...document.querySelectorAll<HTMLButtonElement>("button")]
      .find((button) => button.textContent?.trim() === "Back");
    if (!back) throw new Error("The Autonomous review Back button is unavailable");
    back.scrollIntoView({ block: "center", inline: "center" });
    await new Promise<void>((resolveFrame) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolveFrame()));
    });
    const rectangle = back.getBoundingClientRect();
    const centerX = rectangle.left + rectangle.width / 2;
    const centerY = rectangle.top + rectangle.height / 2;
    const hit = document.elementFromPoint(centerX, centerY);
    return {
      viewportWidth: window.innerWidth,
      documentWidth: document.documentElement.scrollWidth,
      backInsideViewport:
        rectangle.left >= 0
        && rectangle.right <= window.innerWidth,
      backHitTarget:
        hit === back
        || (hit instanceof Node && back.contains(hit)),
    };
  });
  expect(
    geometry.documentWidth,
    "The Autonomous readiness review must not create horizontal page overflow",
  ).toBeLessThanOrEqual(geometry.viewportWidth);
  expect(
    geometry.backInsideViewport,
    "The Back control must remain fully inside the mobile viewport",
  ).toBe(true);
  expect(
    geometry.backHitTarget,
    "The visual center of Back must resolve to the Back control",
  ).toBe(true);
}

test(`${TEST_ID} retires stale results and keeps launch bound to the current server review`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(240_000);
  createMissionIntakeDynamicFixture(testInfo.testId);
  const state: {
    runtime: RuntimeState;
    preflight: PreflightState;
    holdFirstPreflight: boolean;
    delayNextReadyPreflight: boolean;
    releaseFirstPreflight?: () => void;
  } = {
    runtime: "blocked",
    preflight: "blocked",
    holdFirstPreflight: true,
    delayNextReadyPreflight: false,
  };
  await installReadinessStateRoutes(page, state);
  const ledger = createIntakeRequestLedger(page);
  const receipts: IntakeReceiptContext = {
    recorder: interactionActivation,
    testId: TEST_ID,
  };
  try {
    await page.goto("/missions/new/autonomous");
    await chooseAutonomousTitaniumOption(
      autonomousTitaniumSelect(page, /Environment classification/u),
      "local_disposable_lab",
      "keyboard",
    );
    await page
      .getByLabel("Authorized targets or environment references", { exact: false })
      .fill("127.0.0.1");
    await page
      .getByRole("checkbox", {
        name: /I confirm these targets and the selected action policy are authorized/u,
      })
      .check();
    await advanceAutonomousIntake(page, "Outcome and collaboration");
    await advanceAutonomousIntake(page, "Autonomous operating contract");

    const resolvedPromise = page.waitForResponse((response) =>
      response.url().endsWith("/api/v2/registries/intake/resolve")
      && response.request().method() === "POST");
    const preflightPromise = page.waitForResponse((response) =>
      response.url().endsWith("/api/v2/missions/autonomous/preflight")
      && response.request().method() === "POST");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(page.getByRole("button", { name: "Resolving defaults…", exact: true }))
      .toBeDisabled();
    await expect(
      autonomousIntakeGroup(page, "Autonomous operating contract"),
    ).toBeVisible();
    state.releaseFirstPreflight?.();
    expect((await resolvedPromise).status()).toBe(200);
    expect((await preflightPromise).status()).toBe(200);
    await expect(
      autonomousIntakeGroup(page, "Specialist team and execution readiness"),
    ).toBeVisible();

    await advanceAutonomousIntake(
      page,
      "Second Brain context",
      { expectPreflight: true },
    );
    await advanceAutonomousIntake(
      page,
      "Review the resolved mission",
      { expectPreflight: true },
    );
    const review = page.locator(".os-autonomous-readiness");
    const launch = page.getByRole("button", {
      name: "Launch Autonomous Assessment",
      exact: true,
    });
    await expect(review.getByLabel("Autonomous readiness score 51 out of 100"))
      .toBeVisible();
    await expect(review).toContainText("9 failing checks prevent unattended execution");
    await expect(launch).toBeDisabled();

    browserAudit.expectHttpResponse(page, {
      id: "autonomous-intake.readiness.refresh-unavailable",
      transport: "browser",
      method: "POST",
      pathname: "/api/v2/missions/autonomous/preflight",
      query: {},
      status: 503,
      occurrences: 1,
      reason: "Prove a failed replacement review retires stale blockers without reopening launch.",
    });
    state.preflight = "error";
    state.runtime = "ready-a";
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await expect(review).toHaveAttribute(
      "data-readiness-review-state",
      "refreshing",
      { timeout: 15_000 },
    );
    await expect(review).toContainText("retired the old score and blockers");
    await expect(review).not.toContainText("51/100");
    await expect(review).not.toContainText(
      "9 failing checks prevent unattended execution",
    );
    await expect(review).toHaveAttribute(
      "data-readiness-review-state",
      "refresh-failed",
      { timeout: 15_000 },
    );
    await expect(review).toContainText("Autonomous readiness needs a new review");
    await expect(page.locator(".os-state-panel--error[role=\"alert\"]")).toContainText(
      "The replacement Autonomous readiness review could not be completed.",
    );
    await expect(launch).toBeDisabled();
    await expectReviewGeometryFitsViewport(page);

    state.preflight = "degraded";
    await page.getByRole("button", { name: "Back", exact: true }).click();
    await expect(autonomousIntakeGroup(page, "Second Brain context")).toBeVisible();
    await advanceAutonomousIntake(
      page,
      "Review the resolved mission",
      { expectPreflight: true },
    );
    await expect(review.getByLabel("Autonomous readiness score 92 out of 100"))
      .toBeVisible();
    await expect(review).toContainText("Autonomous launch is degraded");
    await expect(review).toContainText("1 advisory check remains");
    await expect(review).not.toContainText("failing check");
    await expect(launch).toBeEnabled();

    state.preflight = "ready";
    state.runtime = "ready-b";
    state.delayNextReadyPreflight = true;
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await expect(review).toHaveAttribute(
      "data-readiness-review-state",
      "refreshing",
      { timeout: 15_000 },
    );
    await expect(review).not.toContainText("92/100");
    await expect(launch).toBeDisabled();
    await expect(review.getByLabel("Autonomous readiness score 100 out of 100"))
      .toBeVisible({ timeout: 15_000 });
    await expect(review).toContainText("Autonomous launch is ready");
    await expect(review).toContainText("no Autonomous launch blocker is reported");
    await expect(launch).toBeEnabled();
    await exerciseAuditDisclosure(
      review.locator("details.os-readiness-other-checks"),
      receipts,
    );
    expect(ledger.count("POST", "/api/v2/missions")).toBe(0);
  } finally {
    ledger.dispose();
  }
});

import {
  expect,
  test,
  type Page,
} from "./support/playwright";
import type { AutonomousMissionPreflight } from "../../src/domain/types/commandOs";
import { startReadyAutonomousIntakeBackend } from "./support/readyAutonomousIntakeBackendController";
import {
  AUTONOMOUS_INTAKE_ROUTE,
  activateAutonomousIntake,
  advanceAutonomousIntake,
  assertAutonomousIntakeGuard,
  autonomousIntakeGroup,
  autonomousTitaniumSelect,
  chooseAutonomousTitaniumOption,
  createIntakeRequestLedger,
  installIntakeApiProxy,
  type IntakeActivationModality,
  type IntakeReceiptContext,
  type IntakeRequestLedger,
} from "./support/autonomousIntake";
import type { ReadyAutonomousIntakeBackend } from "./support/readyAutonomousIntakeBackendController";

const TEST_ID = "e2e.autonomous-intake.launch";
const READY_TARGET = "127.0.0.1";

interface CreatedAutonomousMission {
  readonly mission: {
    readonly id: string;
    readonly title: string;
    readonly journey: "autonomous";
  };
  readonly run: {
    readonly id: string;
    readonly status: "planning";
    readonly journey: "autonomous";
  };
  readonly nextUrl: string;
}

interface PageFetchResult<T> {
  readonly status: number;
  readonly body: T;
}

async function pageFetchJson<T>(
  page: Page,
  pathname: string,
): Promise<PageFetchResult<T>> {
  return page.evaluate(async (path) => {
    const response = await fetch(path, {
      headers: { accept: "application/json" },
    });
    const text = await response.text();
    return {
      status: response.status,
      body: JSON.parse(text) as T,
    };
  }, pathname);
}

async function prepareAutonomousReview(
  page: Page,
  backend: ReadyAutonomousIntakeBackend,
  target: string,
): Promise<AutonomousMissionPreflight> {
  await expect(
    autonomousIntakeGroup(page, "Authorization and exact scope"),
  ).toBeVisible();
  await chooseAutonomousTitaniumOption(
    autonomousTitaniumSelect(page, /Environment classification/u),
    "local_disposable_lab",
    "pointer",
  );
  await page
    .getByLabel("Authorized targets or environment references", { exact: false })
    .fill(target);
  await page
    .getByRole("checkbox", {
      name: /I confirm these targets and the selected action policy are authorized/u,
    })
    .check();

  await advanceAutonomousIntake(page, "Outcome and collaboration");
  await advanceAutonomousIntake(page, "Autonomous operating contract");
  await advanceAutonomousIntake(
    page,
    "Specialist team and execution readiness",
    { expectPreflight: true },
  );

  const team = autonomousIntakeGroup(
    page,
    "Specialist team and execution readiness",
  );
  await expect(team.locator("label.os-check-field")).toHaveCount(
    backend.productAgents.length,
  );
  await page
    .getByRole("button", { name: "Use recommended team", exact: true })
    .click();
  await expect(team.locator('input[type="checkbox"]:checked')).toHaveCount(
    backend.productAgents.length,
  );

  await advanceAutonomousIntake(page, "Second Brain context", {
    expectPreflight: true,
  });
  const context = autonomousIntakeGroup(page, "Second Brain context");
  for (const node of backend.memoryNodes) {
    const checkbox = context.getByRole("checkbox", {
      name: new RegExp(
        node.title.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"),
        "u",
      ),
    });
    await expect(checkbox).toBeEnabled();
    await checkbox.check();
    await expect(checkbox).toBeChecked();
  }

  const review = await advanceAutonomousIntake(
    page,
    "Review the resolved mission",
    { expectPreflight: true },
  );
  if (!review.preflight) {
    throw new Error("Autonomous review did not produce a preflight response");
  }
  const preflight = await review.preflight.json() as AutonomousMissionPreflight;
  await expect(
    autonomousIntakeGroup(page, "Review the resolved mission"),
  ).toBeVisible();
  return preflight;
}

async function expectDurableV2Mission(
  page: Page,
  created: CreatedAutonomousMission,
  expectedContract: AutonomousMissionPreflight["contract"],
): Promise<void> {
  const missionPage = await pageFetchJson<{
    readonly schemaVersion: "2.4";
    readonly items: readonly {
      readonly id: string;
      readonly journey: string;
      readonly runId: string | null;
    }[];
  }>(
    page,
    `/api/v2/missions?query=${encodeURIComponent(created.mission.id)}`,
  );
  expect(missionPage.status).toBe(200);
  expect(missionPage.body.items).toContainEqual(expect.objectContaining({
    id: created.mission.id,
    journey: "autonomous",
    runId: created.run.id,
  }));

  const runtime = await pageFetchJson<{
    readonly schemaVersion: "2.4";
    readonly mission: {
      readonly id: string;
      readonly journey: string;
      readonly allowedTargets: readonly string[];
    };
    readonly runs: readonly {
      readonly id: string;
      readonly missionId: string;
      readonly journey: string;
      readonly status: string;
      readonly statusReason: string | null;
    }[];
  }>(page, `/api/v2/missions/${encodeURIComponent(created.mission.id)}/runtime`);
  expect(runtime.status).toBe(200);
  expect(runtime.body).toMatchObject({
    schemaVersion: "2.4",
    mission: {
      id: created.mission.id,
      journey: "autonomous",
      allowedTargets: [READY_TARGET],
    },
    runs: [expect.objectContaining({
      id: created.run.id,
      missionId: created.mission.id,
      journey: "autonomous",
      status: "planning",
      statusReason:
        "Autonomous contract confirmed; durable planning may proceed without routine input.",
    })],
  });

  const events = await pageFetchJson<{
    readonly schemaVersion: "2.4";
    readonly items: readonly {
      readonly eventType: string;
      readonly mission: {
        readonly id: string;
      };
      readonly runId: string;
      readonly payload: unknown;
    }[];
  }>(
    page,
    `/api/v2/observability/events?missionId=${encodeURIComponent(created.mission.id)}&runId=${encodeURIComponent(created.run.id)}&limit=100`,
  );
  expect(events.status).toBe(200);
  expect(events.body.items).toContainEqual(expect.objectContaining({
    eventType: "run.autonomous_planning_started",
    mission: expect.objectContaining({ id: created.mission.id }),
    runId: created.run.id,
    payload: expect.objectContaining({ contractHash: expectedContract.hash }),
  }));

  const recovery = await pageFetchJson<{
    readonly schemaVersion: "2.4";
    readonly run: {
      readonly id: string;
      readonly missionId: string;
      readonly journey: string;
      readonly status: string;
    };
    readonly actions: readonly {
      readonly kind: string;
      readonly available: boolean;
      readonly command: string | null;
      readonly reason: string;
    }[];
  }>(
    page,
    `/api/v2/operations/runs/${encodeURIComponent(created.run.id)}/recovery`,
  );
  expect(recovery.status).toBe(200);
  expect(recovery.body.run).toMatchObject({
    id: created.run.id,
    missionId: created.mission.id,
    journey: "autonomous",
    status: "planning",
  });
  expect(recovery.body.actions).toContainEqual(expect.objectContaining({
    kind: "terminate",
    available: true,
    command: "cancel",
  }));
  expect(
    recovery.body.actions.find(({ kind }) => kind === "terminate")?.reason,
  ).not.toContain("legacy control plane");
}

async function launchReadyMission(
  page: Page,
  backend: ReadyAutonomousIntakeBackend,
  ledger: IntakeRequestLedger,
  context: IntakeReceiptContext,
  modality: IntakeActivationModality,
): Promise<{ readonly created: CreatedAutonomousMission; readonly idempotencyKey: string }> {
  const preflight = await prepareAutonomousReview(page, backend, READY_TARGET);
  expect(preflight.readiness.status).toBe("ready");
  expect(preflight.readiness.checks.filter(({ status }) => status === "fail"))
    .toEqual([]);
  expect(preflight.contract.version).toBeGreaterThan(0);
  expect(preflight.contract.hash).toMatch(/^[a-f0-9]{64}$/u);
  const canonicalSpecialistAgentIds = backend.productAgents
    .map(({ id }) => id)
    .sort((left, right) => left.localeCompare(right));
  expect(preflight.execution.team.selectedAgentIds).toEqual(
    canonicalSpecialistAgentIds,
  );

  const launch = page.getByRole("button", {
    name: /Launch (?:Complete )?Autonomous (?:Assessment|Engagement)/u,
  });
  await expect(launch).toBeEnabled();
  const createdPromise = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v2/missions")
      && response.request().method() === "POST",
  );
  await activateAutonomousIntake(
    context,
    "autonomous-intake.review.launch-ready",
    "Create one V2-controlled Autonomous mission",
    modality,
    async () => {
      if (modality === "pointer") await launch.click();
      else {
        await launch.focus();
        await launch.press("Enter");
      }
    },
  );
  const createdResponse = await createdPromise;
  expect(createdResponse.status(), await createdResponse.text()).toBe(201);
  const idempotencyKey =
    createdResponse.request().headers()["idempotency-key"] ?? "";
  expect(idempotencyKey).toMatch(
    /^(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|mission-[A-Za-z0-9.-]+)$/u,
  );
  const createBody = createdResponse.request().postDataJSON() as {
    readonly journey: string;
    readonly launch: boolean;
    readonly authorization: {
      readonly authorizationConfirmed: boolean;
      readonly allowedTargets: readonly string[];
    };
    readonly contract: {
      readonly specialistAgentIds: readonly string[];
      readonly contextNodeIds: readonly string[];
    };
    readonly contractReview: {
      readonly version: number;
      readonly hash: string;
    };
  };
  expect(createBody).toMatchObject({
    journey: "autonomous",
    launch: true,
    authorization: {
      authorizationConfirmed: true,
      allowedTargets: [READY_TARGET],
    },
    contract: {
      specialistAgentIds: preflight.execution.team.selectedAgentIds,
      contextNodeIds: backend.memoryNodes.map(({ id }) => id),
    },
    contractReview: {
      version: preflight.contract.version,
      hash: preflight.contract.hash,
    },
  });
  expect(createBody.contractReview).toEqual(preflight.contract);
  expect(ledger.count("POST", "/api/v2/missions")).toBe(1);

  const created = await createdResponse.json() as CreatedAutonomousMission;
  expect(created).toMatchObject({
    mission: { journey: "autonomous" },
    run: { status: "planning", journey: "autonomous" },
  });
  expect(created.nextUrl).toBe(`/missions/${created.mission.id}`);
  await expect.poll(() => new URL(page.url()).pathname).toBe(created.nextUrl);
  await expectDurableV2Mission(page, created, preflight.contract);
  await expect(
    page.getByRole("region", { name: "Selected run status" }),
  ).toContainText("Planning autonomously");

  return { created, idempotencyKey };
}

async function openAutonomousIntake(
  page: Page,
  fromApplication: boolean,
  browserAudit: {
    withExpectedDocumentNavigationTeardown<T>(
      page: Page,
      operation: () => Promise<T>,
    ): Promise<T>;
  },
): Promise<void> {
  if (fromApplication) {
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.goto(AUTONOMOUS_INTAKE_ROUTE),
    );
  } else {
    await page.goto(AUTONOMOUS_INTAKE_ROUTE);
  }
  await expect(
    autonomousIntakeGroup(page, "Authorization and exact scope"),
  ).toBeVisible();
}

test(TEST_ID, async (
  { page, browserAudit, interactionActivation },
  testInfo,
) => {
  test.setTimeout(480_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  const context: IntakeReceiptContext = {
    recorder: interactionActivation,
    testId: TEST_ID,
  };
  const pointerBackend = await startReadyAutonomousIntakeBackend(
    `${testInfo.testId}-pointer`,
  );
  const backends: ReadyAutonomousIntakeBackend[] = [pointerBackend];
  const proxy = await installIntakeApiProxy(page, pointerBackend.baseUrl);
  let pointerLedger: IntakeRequestLedger | undefined;
  let keyboardLedger: IntakeRequestLedger | undefined;
  let blockedLedger: IntakeRequestLedger | undefined;

  try {
    pointerLedger = createIntakeRequestLedger(page);
    await openAutonomousIntake(page, false, browserAudit);
    const pointer = await launchReadyMission(
      page,
      pointerBackend,
      pointerLedger,
      context,
      "pointer",
    );
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.reload(),
    );
    await expect.poll(() => new URL(page.url()).pathname).toBe(
      `/missions/${pointer.created.mission.id}`,
    );
    await expectDurableV2Mission(
      page,
      pointer.created,
      {
        version: (
          pointerLedger.matching("POST", "/api/v2/missions")[0]!.body as {
            contractReview: AutonomousMissionPreflight["contract"];
          }
        ).contractReview.version,
        hash: (
          pointerLedger.matching("POST", "/api/v2/missions")[0]!.body as {
            contractReview: AutonomousMissionPreflight["contract"];
          }
        ).contractReview.hash,
      },
    );
    pointerLedger.dispose();
    pointerLedger = undefined;

    const keyboardBackend = await startReadyAutonomousIntakeBackend(
      `${testInfo.testId}-keyboard`,
    );
    backends.push(keyboardBackend);
    proxy.setBaseUrl(keyboardBackend.baseUrl);
    await openAutonomousIntake(page, true, browserAudit);
    await pointerBackend.stop();
    keyboardLedger = createIntakeRequestLedger(page);
    const keyboard = await launchReadyMission(
      page,
      keyboardBackend,
      keyboardLedger,
      context,
      "keyboard",
    );
    expect(keyboard.idempotencyKey).not.toBe(pointer.idempotencyKey);
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.reload(),
    );
    await expect.poll(() => new URL(page.url()).pathname).toBe(
      `/missions/${keyboard.created.mission.id}`,
    );
    await expectDurableV2Mission(
      page,
      keyboard.created,
      (
        keyboardLedger.matching("POST", "/api/v2/missions")[0]!.body as {
          contractReview: AutonomousMissionPreflight["contract"];
        }
      ).contractReview,
    );
    keyboardLedger.dispose();
    keyboardLedger = undefined;

    const blockedBackend = await startReadyAutonomousIntakeBackend(
      `${testInfo.testId}-blocked`,
    );
    backends.push(blockedBackend);
    proxy.setBaseUrl(blockedBackend.baseUrl);
    await openAutonomousIntake(page, true, browserAudit);
    await keyboardBackend.stop();
    blockedLedger = createIntakeRequestLedger(page);
    const blockedPreflight = await prepareAutonomousReview(
      page,
      blockedBackend,
      "lab:unresolved-autonomous-target",
    );
    expect(blockedPreflight.readiness.status).toBe("blocked");
    const blockedLaunch = page.getByRole("button", {
      name: /Launch (?:Complete )?Autonomous (?:Assessment|Engagement)/u,
    });
    await assertAutonomousIntakeGuard(
      context,
      "autonomous-intake.review.launch-blocked-guard",
      "Blocked launch remains disabled and sends no mission request",
      async () => {
        await expect(blockedLaunch).toBeDisabled();
        expect(blockedLedger?.count("POST", "/api/v2/missions")).toBe(0);
        await page.waitForTimeout(250);
        expect(blockedLedger?.count("POST", "/api/v2/missions")).toBe(0);
        await expect(
          autonomousIntakeGroup(page, "Review the resolved mission")
            .locator(".os-readiness-summary"),
        ).toContainText("blocked");
      },
    );
  } finally {
    pointerLedger?.dispose();
    keyboardLedger?.dispose();
    blockedLedger?.dispose();
    if (!page.isClosed()) {
      await browserAudit.closePageBeforeDependencyShutdown(page);
    }
    await proxy.dispose();
    for (const backend of backends) await backend.stop();
  }
});

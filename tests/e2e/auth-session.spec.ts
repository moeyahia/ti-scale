import { expect, test } from "./support/playwright";
import { E2E_OPERATOR_TOKEN } from "./support/environment";

const TEST_ID = "e2e.auth.session";

test.use({ storageState: { cookies: [], origins: [] } });

test(`${TEST_ID} signs in through the real local session and signs out cleanly`, async ({ page, browserAudit }) => {
  browserAudit.expectHttpResponse(page, {
    id: "auth.session.invalid-token",
    transport: "browser",
    method: "POST",
    pathname: "/api/v2/auth/session",
    query: {},
    status: 401,
    occurrences: 1,
    reason: "Prove an invalid local operator token fails closed exactly once.",
  });
  await page.goto("/");
  const token = page.getByLabel("Local operator token", { exact: true });
  const signIn = page.getByRole("button", { name: "Sign in to Ti-Scale", exact: true });
  await expect(token).toBeVisible();
  await token.fill("incorrect-e2e-token-that-is-long-enough");
  await signIn.click();
  await expect(page.getByText("Operator token not accepted", { exact: true })).toBeVisible();
  await token.fill(E2E_OPERATOR_TOKEN);
  await signIn.click();
  await expect(page.locator("main#ti-scale-content")).toBeVisible();
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  const commandCenterCore = page.locator("[data-ti-transformer-core='true']");
  await expect(commandCenterCore).toHaveCount(1);
  await expect(commandCenterCore).toHaveAttribute("data-ti-particle-artwork", "operator-approved");
  await expect.poll(
    () => commandCenterCore.getAttribute("data-ti-particle-status"),
    { timeout: 20_000 },
  ).not.toBe("loading");
  const particleStatus = await commandCenterCore.getAttribute("data-ti-particle-status");
  expect(["active", "fallback"]).toContain(particleStatus);
  if (particleStatus === "active") {
    await expect(commandCenterCore.locator("canvas.particle-core-runtime__canvas")).toHaveCount(1);
    await expect.poll(async () => Number(
      await commandCenterCore.getAttribute("data-ti-point-count") ?? "0",
    )).toBeGreaterThan(0);
  } else {
    await expect(commandCenterCore.getByText("Particle field unavailable", { exact: true })).toBeVisible();
    const fallbackReason = commandCenterCore.locator(".ti-command-particle-core__fallback small");
    await expect(fallbackReason).toBeVisible();
    await expect.poll(async () => (await fallbackReason.textContent())?.trim().length ?? 0)
      .toBeGreaterThan(20);
  }
  const storedValues = await page.evaluate(() => ({ ...localStorage, ...sessionStorage }));
  expect(Object.values(storedValues)).not.toContain(E2E_OPERATOR_TOKEN);
  const cookies = await page.context().cookies();
  const sessionCookie = cookies.find((cookie) => cookie.name === "ti_scale_session");
  const csrfCookie = cookies.find((cookie) => cookie.name === "ti_scale_csrf");
  expect(sessionCookie?.httpOnly).toBe(true);
  expect(csrfCookie?.httpOnly).toBe(false);

  await page.evaluate(() => {
    sessionStorage.setItem(
      "ti-scale.recovery.mutation-intent.v1.run-auth-boundary",
      "retained-recovery-intent",
    );
    sessionStorage.setItem(
      "ti-scale.research.promotion-intent.v1.operator.experiment-auth-boundary",
      "retained-research-intent",
    );
    sessionStorage.setItem(
      "ti-scale.auth-boundary.unrelated",
      "keep",
    );
  });
  await page.getByRole("button", { name: "Sign out of Ti-Scale", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Enter Ti-Scale", exact: true })).toBeVisible();
  expect((await page.context().cookies()).some((cookie) => cookie.name === "ti_scale_session")).toBe(false);
  expect(await page.evaluate(() => ({
    recovery: Object.keys(sessionStorage).some((key) =>
      key.startsWith("ti-scale.recovery.mutation-intent.v1.")),
    research: Object.keys(sessionStorage).some((key) =>
      key.startsWith("ti-scale.research.promotion-intent.v1.")),
    unrelated: sessionStorage.getItem("ti-scale.auth-boundary.unrelated"),
  }))).toEqual({
    recovery: false,
    research: false,
    unrelated: "keep",
  });
});

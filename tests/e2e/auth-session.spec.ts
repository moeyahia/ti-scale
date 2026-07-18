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
  const commandCenterAmbient = page.locator(".os-brand-media--command img");
  await expect(commandCenterAmbient).toHaveCount(1);
  await expect.poll(() => commandCenterAmbient.evaluate((image: HTMLImageElement) => (
    image.complete && image.naturalWidth > 0
  ))).toBe(true);
  const storedValues = await page.evaluate(() => ({ ...localStorage, ...sessionStorage }));
  expect(Object.values(storedValues)).not.toContain(E2E_OPERATOR_TOKEN);
  const cookies = await page.context().cookies();
  const sessionCookie = cookies.find((cookie) => cookie.name === "ti_scale_session");
  const csrfCookie = cookies.find((cookie) => cookie.name === "ti_scale_csrf");
  expect(sessionCookie?.httpOnly).toBe(true);
  expect(csrfCookie?.httpOnly).toBe(false);

  await page.getByRole("button", { name: "Sign out of Ti-Scale", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Enter Ti-Scale", exact: true })).toBeVisible();
  expect((await page.context().cookies()).some((cookie) => cookie.name === "ti_scale_session")).toBe(false);
});

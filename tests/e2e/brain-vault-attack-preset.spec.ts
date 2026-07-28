import { expect, test } from "./support/playwright";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import { createOperatorPreferencesFixture } from "./support/operatorPreferencesFixture";

const TEST_ID = "e2e.brain-vault.attack-knowledge-preset";

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  // This journey owns its actor-bound eligibility precondition. It must not
  // pass only because another specification happened to seed a preference in
  // the shared disposable matrix database first.
  createOperatorPreferencesFixture(canonicalFixtureNamespace(
    testInfo,
    "brain-vault-attack-preset-operator-profile",
  ));
});

test("reviews and deliberately activates the fixed Attack Knowledge Vault policy", async ({ page, browserAudit }, testInfo) => {
  // The first browser project deliberately exercises three separate,
  // hash-gated filesystem-policy mutations plus their round-trip checks. Keep
  // each action on the normal 7.5-second assertion budget while allowing the
  // complete audited journey to finish without treating expected work as a
  // stuck page.
  test.setTimeout(120_000);
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_ID });

  await page.goto("/brain/vault");
  await expect(page.getByRole("heading", { level: 1, name: "Obsidian Vault" })).toBeVisible();
  const card = page.locator(".brain-attack-vault-preset");
  await expect(card.getByRole("heading", { level: 2, name: "Ti-Scale Attack Knowledge Vault" })).toBeVisible();
  await expect(card.getByText("Attack-Knowledge-Vault", { exact: true })).toBeVisible();
  await expect(card.getByText(/restricted withheld/u)).toBeVisible();

  const categories = card.getByText("Review projected categories and folders", { exact: true });
  await categories.click();
  await expect(card.getByText(/Reusable categories:/u)).toBeVisible();
  await expect(card.getByText(/Technology Products/u)).toBeVisible();
  await expect(card.getByText(/IP addresses and CIDRs/u)).toBeVisible();
  await categories.click();

  const activeStatus = card.getByText("Attack Knowledge Vault is active", { exact: true });
  const includeConfirmed = card.getByLabel("Include operator-confirmed attack knowledge");
  if (await activeStatus.count() > 0) {
    await expect(activeStatus).toBeVisible();
  } else {
    await includeConfirmed.check();
    await expect(card.getByText("verified + confirmed", { exact: true })).toBeVisible();
    await includeConfirmed.uncheck();
    await expect(card.getByText("verified", { exact: true })).toBeVisible();

    const permission = card.getByLabel("Grant Attack Knowledge Vault filesystem permission");
    const acknowledgement = card.getByLabel("Acknowledge Attack Knowledge Vault activation");
    const activate = card.getByRole("button", { name: "Activate Attack Knowledge Vault" });
    await expect(activate).toBeDisabled();
    await permission.check();
    await acknowledgement.check();
    await expect(activate).toBeDisabled();

    await card.getByRole("button", { name: "Test preset path" }).click();
    await expect(card.getByText("Preset path round-trip verified", { exact: true })).toBeVisible();
    await expect(activate).toBeEnabled();

    const activationRequestPromise = page.waitForRequest((request) => (
      request.method() === "POST"
      && new URL(request.url()).pathname === "/api/v2/brain/vault/attack-knowledge-preset/activate"
    ));
    await activate.click();
    const activationRequest = await activationRequestPromise;
    const body = activationRequest.postDataJSON() as Record<string, unknown>;
    expect(body).toMatchObject({
      includeConfirmed: false,
      permissionGranted: true,
      activationAcknowledged: true,
    });
    expect(body.expectedPolicyHash).toMatch(/^[a-f0-9]{64}$/u);
    await expect(activeStatus).toBeVisible();
    await expect(card.getByText(/No target, mission, run, IP address, raw evidence, or restricted memory was added/u)).toBeVisible();
  }

  if (await includeConfirmed.isDisabled()) {
    await expect(card.getByText(/includes verified and explicitly confirmed reusable attack knowledge/u)).toBeVisible();
  } else {
    await includeConfirmed.check();
    await expect(card.getByText("verified + confirmed", { exact: true })).toBeVisible();
    await expect(card.getByText(/without replacing this Vault/u)).toBeVisible();
    const amendmentPermission = card.getByLabel("Grant Attack Knowledge Vault filesystem permission");
    const amendmentAcknowledgement = card.getByLabel("Acknowledge Attack Knowledge Vault confirmed scope amendment");
    const amend = card.getByRole("button", { name: "Apply confirmed knowledge scope" });
    await amendmentPermission.check();
    await amendmentAcknowledgement.check();
    await card.getByRole("button", { name: "Test preset path" }).click();
    await expect(amend).toBeEnabled();
    const amendmentRequestPromise = page.waitForRequest((request) => (
      request.method() === "POST"
      && new URL(request.url()).pathname === "/api/v2/brain/vault/attack-knowledge-preset/amend"
    ));
    await amend.click();
    const amendmentRequest = await amendmentRequestPromise;
    const amendmentBody = amendmentRequest.postDataJSON() as Record<string, unknown>;
    expect(amendmentBody).toMatchObject({
      includeConfirmed: true,
      permissionGranted: true,
      amendmentAcknowledged: true,
    });
    expect(amendmentBody.expectedCurrentPolicyHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(amendmentBody.expectedTargetPolicyHash).toMatch(/^[a-f0-9]{64}$/u);
    await expect(card.getByText(/same Vault connection and path/u)).toBeVisible();
    await expect(card.getByText(/includes verified and explicitly confirmed reusable attack knowledge/u)).toBeVisible();
  }

  const includeOperatorProfile = card.getByLabel("Include Operator Preferences and Profile");
  if (await includeOperatorProfile.isDisabled()) {
    await expect(card.getByText(/separately consented Operator Preferences and Profile/u)).toBeVisible();
  } else {
    await includeOperatorProfile.check();
    await expect(card.getByText(/explicitly confirmed preference, operator, and application-domain/u)).toBeVisible();
    await expect(card.getByText(/Targets, engagement names, addresses, and operational records remain excluded/u)).toBeVisible();

    const profilePermission = card.getByLabel("Grant Attack Knowledge Vault filesystem permission");
    const profileAcknowledgement = card.getByLabel("Acknowledge Operator Profile Vault scope amendment");
    const addProfile = card.getByRole("button", { name: "Add Operator Profile to Vault" });
    await profilePermission.check();
    await profileAcknowledgement.check();
    await card.getByRole("button", { name: "Test preset path" }).click();
    await expect(addProfile).toBeEnabled();
    const profileRequestPromise = page.waitForRequest((request) => (
      request.method() === "POST"
      && new URL(request.url()).pathname === "/api/v2/brain/vault/attack-knowledge-preset/amend"
    ));
    await addProfile.click();
    const profileRequest = await profileRequestPromise;
    expect(profileRequest.postDataJSON()).toMatchObject({
      includeConfirmed: true,
      includeOperatorProfile: true,
      permissionGranted: true,
      operatorProfileAcknowledged: true,
    });
    await expect(card.getByText(/Operator Preferences and Profile are now eligible in the 10 Operator folder/u)).toBeVisible();
    await expect(card.getByText(/separately consented Operator Preferences and Profile/u)).toBeVisible();
  }

  await expect(page.getByRole("heading", { level: 2, name: "Attack-Knowledge-Vault" })).toBeVisible();
  await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByText("Attack Knowledge Vault is active", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: "Attack-Knowledge-Vault" })).toBeVisible();
});

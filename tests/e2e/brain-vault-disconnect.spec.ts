import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createDatabaseConnection } from "../../server/db";
import { expect, test, type Page } from "./support/playwright";
import { createBrainVaultFixture, readBrainVaultFixture, type BrainVaultFixture } from "./support/brainVaultFixture";
import { E2E_DATABASE_PATH, E2E_VAULT_ROOT } from "./support/environment";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.brain-vault.disconnect-projection";

test.describe.configure({ mode: "serial" });

async function connect(page: Page, fixture: BrainVaultFixture, beforeConnect?: () => void) {
  await page.getByLabel("Display name").fill(fixture.displayName);
  await page.getByLabel("Path inside the allowed root").fill(fixture.relativePath);
  await page.getByLabel("Grant explicit filesystem permission").check();
  await page.getByRole("button", { name: "Test write, read, rename, and delete" }).click();
  await expect(page.getByText("Round-trip verified", { exact: true })).toBeVisible();
  beforeConnect?.();
  await page.getByRole("button", { name: "Connect verified vault" }).click();
  await expect(page.getByRole("heading", { level: 2, name: fixture.relativePath })).toBeVisible();
}

function fileHash(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

test("disconnects one Vault projection through the audited confirmation flow without touching files", async ({ page, browserAudit }, testInfo) => {
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_ID });
  const namespace = canonicalFixtureNamespace(testInfo, "brain-vault-disconnect");
  const retiring = createBrainVaultFixture(`${namespace}-retiring`);
  const replacement = createBrainVaultFixture(`${namespace}-replacement`);
  const preservingPath = join(E2E_VAULT_ROOT, retiring.relativePath, `operator-preserved-${namespace}.md`);
  const preservingText = "# Operator-owned note\n\nDisconnect must preserve these exact bytes.\n";
  let preservingHash = "";

  await page.goto("/brain/vault");
  await expect(page.getByRole("heading", { level: 1, name: "Obsidian Vault" })).toBeVisible();
  await connect(page, retiring, () => {
    // The round-trip proof creates the directory. Place the operator-owned
    // note before the watcher is connected so this test isolates disconnect
    // semantics from the separate connected-note import/quarantine contract.
    writeFileSync(preservingPath, preservingText, { encoding: "utf8", mode: 0o600 });
    preservingHash = fileHash(preservingPath);
  });
  await connect(page, replacement);

  const retiringHeading = page.getByRole("heading", { level: 2, name: retiring.relativePath });
  const retiringCard = page.locator(".brain-vault-connections > .os-card").filter({ has: retiringHeading });
  await retiringCard.getByRole("button", { name: "Disconnect projection" }).click();
  let dialog = page.getByRole("dialog", { name: `Disconnect ${retiring.displayName}` });
  await expect(dialog).toContainText("It will not delete the Vault, rewrite a note, remove an attachment, or change canonical Second Brain memory.");
  await expect(dialog.getByText("A health-verified replacement remains active", { exact: true })).toBeVisible();
  await expect(dialog.getByLabel("Allow controlled degraded Obsidian projection")).toHaveCount(0);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
  await expect(retiringCard.getByRole("button", { name: "Disconnect projection" })).toBeFocused();

  await retiringCard.getByRole("button", { name: "Disconnect projection" }).click();
  dialog = page.getByRole("dialog", { name: `Disconnect ${retiring.displayName}` });
  const confirm = dialog.getByRole("button", { name: "Disconnect Vault projection" });
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel("Reason for disconnecting").fill("Retire this generic fixture after its health-verified replacement is connected.");
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel("Acknowledge Vault disconnect effects").check();
  await expect(confirm).toBeEnabled();

  const requestPromise = page.waitForRequest((request) => (
    request.method() === "POST"
    && new URL(request.url()).pathname.endsWith("/disconnect")
  ));
  await confirm.click();
  const request = await requestPromise;
  expect(request.headers()["idempotency-key"]).toBeTruthy();
  expect(request.postDataJSON()).toMatchObject({
    expectedUpdatedAt: expect.any(String),
    reason: "Retire this generic fixture after its health-verified replacement is connected.",
    disconnectAcknowledged: true,
    allowProjectionDegraded: false,
    controlPlane: "ti_scale",
  });

  await expect(page.getByRole("heading", { level: 2, name: "Retired Vault connections" })).toBeVisible();
  const retiredCard = page.locator(".brain-vault-retired-card").filter({
    has: page.getByRole("heading", { level: 2, name: retiring.relativePath }),
  });
  await expect(retiredCard).toContainText("Future synchronization");
  await expect(retiredCard).toContainText("Stopped");
  await expect(page.getByRole("status").filter({ hasText: "no Vault files or notes were changed" })).toBeVisible();
  expect(existsSync(preservingPath)).toBe(true);
  expect(fileHash(preservingPath)).toBe(preservingHash);
  expect(readFileSync(preservingPath, "utf8")).toBe(preservingText);

  const persisted = readBrainVaultFixture(retiring);
  expect(persisted.connection?.status).toBe("disconnected");
  if (!E2E_DATABASE_PATH) throw new Error("Vault disconnect E2E requires an isolated V2 database");
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    const audit = database.prepare(`
      SELECT reason, details_json AS detailsJson
      FROM audit_records
      WHERE action = 'vault.connection.disconnected' AND resource_id = ?
      ORDER BY rowid DESC LIMIT 1
    `).get(persisted.connection!.id) as { reason: string; detailsJson: string } | undefined;
    expect(audit?.reason).toBe("Retire this generic fixture after its health-verified replacement is connected.");
    expect(JSON.parse(audit!.detailsJson)).toMatchObject({ filesDeleted: 0, notesRewritten: 0, syncStopped: true });
    expect(audit!.detailsJson).not.toContain(persisted.vaultDirectory);
  } finally {
    database.close();
  }

  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  await expect(page.locator(".brain-vault-retired-card").filter({
    has: page.getByRole("heading", { level: 2, name: retiring.relativePath }),
  })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: replacement.relativePath })).toBeVisible();
  expect(fileHash(preservingPath)).toBe(preservingHash);
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });
});

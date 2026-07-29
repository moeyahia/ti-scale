import { chromium, type FullConfig } from "@playwright/test";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { E2E_API_URL, E2E_AUTH_STATE, E2E_OPERATOR_TOKEN } from "./support/environment";

export default async function globalSetup(_config: FullConfig): Promise<void> {
  // Authenticate through a real browser context so the exact HttpOnly,
  // SameSite, path, and expiry attributes issued by the server become the
  // storage-state source of truth. This also avoids transport-specific cookie
  // parsing differences between Playwright's Node and Bun API clients.
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(new URL("/api/v2/health", E2E_API_URL).toString(), { waitUntil: "domcontentloaded" });
    const result = await page.evaluate(async ({ endpoint, operatorToken }) => {
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "include",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ operatorToken }),
      });
      return {
        ok: response.ok,
        status: response.status,
        text: await response.text(),
      };
    }, {
      endpoint: new URL("/api/v2/auth/session", E2E_API_URL).toString(),
      operatorToken: E2E_OPERATOR_TOKEN,
    });
    if (!result.ok) {
      throw new Error(`Real V2 E2E sign-in failed with HTTP ${result.status}: ${result.text}`);
    }
    const body = JSON.parse(result.text) as { authenticated?: boolean };
    if (body.authenticated !== true) throw new Error("Real V2 E2E sign-in did not return an authenticated session");
    mkdirSync(dirname(E2E_AUTH_STATE), { recursive: true });
    await context.storageState({ path: E2E_AUTH_STATE });
    chmodSync(E2E_AUTH_STATE, 0o600);
  } finally {
    await context.close();
    await browser.close();
  }
}

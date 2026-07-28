import { chromium, type FullConfig } from "@playwright/test";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { resolveOperatorToken } from "../../server/auth/OperatorTokenConfiguration";
import {
  E2E_API_URL,
  E2E_AUTH_STATE,
} from "./support/environment";

const LIVE_OPERATOR_TOKEN_FILE = "/etc/ti-scale/operator-token";

/**
 * Authenticate the live proof through the same operator-token exchange used
 * by the product. Only the resulting HttpOnly session cookie is serialized;
 * the operator token is read from its private root-owned file and is never
 * placed in Playwright configuration, command arguments, reports, or traces.
 */
export default async function live3132GlobalSetup(
  _config: FullConfig,
): Promise<void> {
  const operatorToken = resolveOperatorToken({
    TI_SCALE_OPERATOR_TOKEN_FILE: LIVE_OPERATOR_TOKEN_FILE,
  });
  if (!operatorToken) {
    throw new Error("The live Ti-Scale operator credential is unavailable");
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(
      new URL("/api/v2/health", E2E_API_URL).toString(),
      { waitUntil: "domcontentloaded" },
    );
    const result = await page.evaluate(
      async ({ endpoint, token }) => {
        const response = await fetch(endpoint, {
          method: "POST",
          credentials: "include",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ operatorToken: token }),
        });
        return {
          ok: response.ok,
          status: response.status,
          text: await response.text(),
        };
      },
      {
        endpoint: new URL("/api/v2/auth/session", E2E_API_URL).toString(),
        token: operatorToken,
      },
    );
    if (!result.ok) {
      throw new Error(
        `Live Ti-Scale sign-in failed with HTTP ${result.status}: ${result.text}`,
      );
    }
    const body = JSON.parse(result.text) as { readonly authenticated?: boolean };
    if (body.authenticated !== true) {
      throw new Error("Live Ti-Scale sign-in did not create a session");
    }
    mkdirSync(dirname(E2E_AUTH_STATE), { recursive: true });
    await context.storageState({ path: E2E_AUTH_STATE });
    chmodSync(E2E_AUTH_STATE, 0o600);
  } finally {
    await context.close();
    await browser.close();
  }
}

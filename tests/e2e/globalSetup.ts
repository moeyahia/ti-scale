import { request, type FullConfig } from "@playwright/test";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { E2E_API_URL, E2E_AUTH_STATE, E2E_OPERATOR_TOKEN } from "./support/environment";

export default async function globalSetup(_config: FullConfig): Promise<void> {
  const context = await request.newContext({ baseURL: E2E_API_URL });
  try {
    const response = await context.post("/api/v2/auth/session", {
      data: { operatorToken: E2E_OPERATOR_TOKEN },
      headers: { Accept: "application/json" },
    });
    if (!response.ok()) {
      throw new Error(`Real V2 E2E sign-in failed with HTTP ${response.status()}: ${await response.text()}`);
    }
    const body = await response.json() as { authenticated?: boolean };
    if (body.authenticated !== true) throw new Error("Real V2 E2E sign-in did not return an authenticated session");
    mkdirSync(dirname(E2E_AUTH_STATE), { recursive: true });
    await context.storageState({ path: E2E_AUTH_STATE });
    chmodSync(E2E_AUTH_STATE, 0o600);
  } finally {
    await context.dispose();
  }
}

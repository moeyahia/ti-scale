import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const playwrightConfig = readFileSync(new URL("../../../playwright.config.ts", import.meta.url), "utf8");
const environment = readFileSync(new URL("../../../tests/e2e/support/environment.ts", import.meta.url), "utf8");

describe("standalone browser-server isolation", () => {
  test("never reuses a prior invocation's API or UI process", () => {
    expect(playwrightConfig).not.toContain("reuseExistingServer: !process.env.CI");
    expect(playwrightConfig.match(/reuseExistingServer:\s*false/gu)).toHaveLength(3);
    expect(playwrightConfig).toContain("Every invocation owns a unique database");
  });

  test("uses invocation-owned ports and authentication state", () => {
    expect(playwrightConfig).toContain("TI_SCALE_PORT: localApiPort");
    expect(playwrightConfig).toContain("--port ${localUiPort}");
    expect(playwrightConfig).toContain("TI_SCALE_API_ORIGIN: localApiServerUrl.origin");
    expect(playwrightConfig).not.toContain('TI_SCALE_PORT: "43141"');
    expect(environment).toContain("`auth-state-${E2E_RUN_ID}.json`");
    expect(environment).not.toContain("ti-scale-e2e-auth-state.json");
  });
});

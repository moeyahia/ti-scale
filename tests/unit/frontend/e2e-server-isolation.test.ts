import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const playwrightConfig = readFileSync(new URL("../../../playwright.config.ts", import.meta.url), "utf8");
const liveReadOnlyConfig = readFileSync(new URL("../../../playwright.live-readonly.config.ts", import.meta.url), "utf8");
const environment = readFileSync(new URL("../../../tests/e2e/support/environment.ts", import.meta.url), "utf8");
const managedStaticLauncher = readFileSync(new URL("../../../scripts/start-managed-e2e-static-server.ts", import.meta.url), "utf8");
const managedApiLauncher = readFileSync(new URL("../../../scripts/start-managed-e2e-api-server.ts", import.meta.url), "utf8");
const managedViteLauncher = readFileSync(new URL("../../../scripts/start-managed-e2e-vite-server.ts", import.meta.url), "utf8");
const playwrightRunner = readFileSync(new URL("../../../scripts/run-playwright-tests.ts", import.meta.url), "utf8");
const globalTeardown = readFileSync(new URL("../../../tests/e2e/globalTeardown.ts", import.meta.url), "utf8");
const packageJson = JSON.parse(
  readFileSync(new URL("../../../package.json", import.meta.url), "utf8"),
) as { readonly scripts?: Readonly<Record<string, string>> };

describe("standalone browser-server isolation", () => {
  test("never reuses a prior invocation's API or UI process", () => {
    expect(playwrightConfig).not.toContain("reuseExistingServer: !process.env.CI");
    expect(playwrightConfig.match(/reuseExistingServer:\s*false/gu)).toHaveLength(3);
    expect(playwrightConfig).toContain("Every invocation owns a unique database");
  });

  test("uses invocation-owned ports and authentication state", () => {
    expect(playwrightConfig).toContain("TI_SCALE_PORT: localApiPort");
    expect(playwrightConfig).toContain("TI_SCALE_E2E_UI_PORT: localUiPort");
    expect(playwrightConfig).toContain("TI_SCALE_API_ORIGIN: localApiServerUrl.origin");
    expect(playwrightConfig).toContain(
      "TI_SCALE_PROVIDER_CONFIG_ROOT: E2E_PROVIDER_CONFIG_ROOT",
    );
    expect(playwrightConfig).toContain(
      "TI_SCALE_SCRIPT_SOURCE_ROOT: E2E_SCRIPT_SOURCE_ROOT",
    );
    expect(playwrightConfig).not.toContain('TI_SCALE_PORT: "43141"');
    expect(environment).toContain("`auth-state-${E2E_RUN_ID}.json`");
    expect(environment).not.toContain("ti-scale-e2e-auth-state.json");
  });

  test("keeps inherited and inline secrets out of reportable web-server config", () => {
    expect(playwrightConfig).not.toContain("...process.env");
    expect(playwrightConfig).not.toContain("TI_SCALE_OPERATOR_TOKEN:");
    expect(playwrightConfig).not.toContain("TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY:");
    expect(playwrightConfig).toContain("TI_SCALE_OPERATOR_TOKEN_FILE: managedOperatorTokenFile");
    expect(playwrightConfig).toContain(
      "TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE:",
    );
    expect(playwrightConfig).toContain("managedResearchIntegrityKeyFile");
    expect(playwrightConfig.match(/managedWebServerEnvironment\(\{/gu)).toHaveLength(3);
    expect(playwrightConfig).toContain("assertManagedE2EParentEnvironmentSafe(process.env)");
    for (const launcher of [
      managedStaticLauncher,
      managedApiLauncher,
      managedViteLauncher,
    ]) {
      expect(launcher).toContain("managedE2EChildEnvironment");
      expect(launcher).not.toContain("env: process.env");
    }
  });

  test("serves one direct invocation-owned release-profile build without publishing a retained release", () => {
    expect(playwrightConfig).toContain(
      'command: "bun run scripts/start-managed-e2e-static-server.ts"',
    );
    expect(playwrightConfig).toContain(
      "TI_SCALE_E2E_STATIC_BUILD_ID: managedStaticBuildId",
    );
    expect(playwrightConfig).toContain("TI_SCALE_DIST_ROOT: releaseBuildRoot");
    expect(playwrightConfig).not.toContain("release:static:stage");
    expect(playwrightConfig).not.toContain("release:static:activate");
    expect(playwrightConfig).not.toContain("TI_SCALE_STATIC_RELEASE_ROOT");
    expect(managedStaticLauncher).toContain(
      "resolveManagedE2EStaticBuild(process.env, { requireBuiltArtifact: true })",
    );
    expect(managedStaticLauncher).toContain("rmSync(dist, { recursive: true, force: true })");
    expect(managedStaticLauncher).toContain("node_modules/vite/bin/vite.js");
    expect(managedStaticLauncher).not.toContain("bunx");
    expect(managedStaticLauncher).not.toContain("StaticArtifactReleaseStore");
    expect(playwrightConfig).toContain(
      'globalTeardown: "./tests/e2e/globalTeardown.ts"',
    );
    expect(globalTeardown).toContain(
      "disposeManagedE2EStaticBuilds(E2E_RUN_ID)",
    );
    expect(globalTeardown).toContain("disposeManagedE2EInvocation()");
    expect(playwrightRunner).toContain("disposeManagedE2EStaticBuilds(E2E_RUN_ID)");
    expect(playwrightRunner).toContain("disposeManagedE2EInvocation()");
    expect(environment).toContain(
      "`${E2E_DATABASE_PATH!}.operational-hazard-hmac`",
    );
    expect(environment).toContain("E2E_PROVIDER_CONFIG_ROOT");
    expect(environment).toContain("E2E_SCRIPT_SOURCE_ROOT");
  });

  test("gives the live 3132 proof no managed server or credential-bearing artifacts", () => {
    expect(playwrightConfig).toContain('testIgnore: "live-readonly-3132.spec.ts"');
    expect(liveReadOnlyConfig).toContain('testMatch: "live-readonly-3132.spec.ts"');
    expect(liveReadOnlyConfig).not.toContain('testIgnore: "live-readonly-3132.spec.ts"');
    expect(liveReadOnlyConfig).toContain('webServer: undefined');
    expect(liveReadOnlyConfig).toContain('screenshot: "off"');
    expect(liveReadOnlyConfig).toContain('trace: "off"');
    expect(liveReadOnlyConfig).toContain('video: "off"');
    expect(liveReadOnlyConfig).not.toContain("E2E_OPERATOR_TOKEN");
  });

  test("keeps Playwright on Node so browser workers always return a reapable result", () => {
    for (const scriptName of [
      "test:e2e",
      "test:e2e:accessibility",
      "test:e2e:release-local",
      "test:e2e:headed",
    ]) {
      const command = packageJson.scripts?.[scriptName];
      expect(command, `${scriptName} must remain declared`).toBeString();
      expect(command).toContain("scripts/run-playwright-tests.ts");
      expect(command).not.toContain(
        "bun ./node_modules/@playwright/test/cli.js test",
      );
      expect(command).not.toContain("bunx --bun playwright");
      expect(command).not.toMatch(/(?:^|&&\s*)playwright test/u);
    }
  });
});

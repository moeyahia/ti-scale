import { defineConfig } from "@playwright/test";
import { resolve } from "node:path";
import {
  E2E_AUTH_STATE,
  E2E_DATA_ROOT,
  E2E_DATABASE_PATH,
  E2E_PROVIDER_CONFIG_ROOT,
  E2E_RUN_ID,
  E2E_SCRIPT_SOURCE_ROOT,
  E2E_VAULT_ROOT,
  assertManagedE2EInvocationPaths,
  prepareManagedE2EOperatorTokenFile,
  prepareManagedE2EResearchIntegrityKeyFile,
} from "./tests/e2e/support/environment";
import { managedWebServerEnvironment } from "./tests/e2e/support/managedWebServerEnvironment";
import { assertManagedE2EParentEnvironmentSafe } from "./scripts/managed-e2e-child-environment";
import { performanceEvidenceRunDirectory } from "./tests/performance/performanceProvenance";

const baseURL = process.env.TI_SCALE_E2E_BASE_URL?.trim()
  ?? "http://127.0.0.1:43880";
const apiURL = process.env.TI_SCALE_E2E_API_URL?.trim() ?? baseURL;
const base = new URL(baseURL);
const api = new URL(apiURL);
const loopback = (hostname: string): boolean =>
  hostname === "localhost"
  || hostname === "::1"
  || hostname === "[::1]"
  || /^127(?:\.\d{1,3}){3}$/u.test(hostname);
if (
  base.protocol !== "http:"
  || api.protocol !== "http:"
  || base.username.length > 0
  || base.password.length > 0
  || api.username.length > 0
  || api.password.length > 0
  || !loopback(base.hostname)
  || !loopback(api.hostname)
  || base.origin !== api.origin
) {
  throw new Error(
    "The browser-performance server must use one explicit loopback HTTP origin",
  );
}
assertManagedE2EParentEnvironmentSafe(process.env);
assertManagedE2EInvocationPaths();

const managedOperatorTokenFile = prepareManagedE2EOperatorTokenFile();
const managedResearchIntegrityKeyFile =
  prepareManagedE2EResearchIntegrityKeyFile();
const bind = base.hostname.replace(/^\[|\]$/gu, "") === "localhost"
  ? "127.0.0.1"
  : base.hostname.replace(/^\[|\]$/gu, "");
const port = base.port || "80";
const evidenceRunId = E2E_RUN_ID;
const evidenceRoot = performanceEvidenceRunDirectory(
  resolve(import.meta.dirname),
  evidenceRunId,
);
const managedStaticBuildId = `e2e-${evidenceRunId.slice(0, 108)}-${process.pid}`;
const releaseBuildRoot = resolve(
  E2E_DATA_ROOT,
  `static-build-${managedStaticBuildId}`,
);

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "performance-web-vitals.spec.ts",
  globalSetup: "./tests/e2e/globalSetup.ts",
  globalTeardown: "./tests/e2e/globalTeardown.ts",
  outputDir: resolve(evidenceRoot, "playwright"),
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  timeout: 10 * 60_000,
  expect: { timeout: 30_000 },
  reporter: [
    ["line"],
    ["html", {
      outputFolder: resolve(evidenceRoot, "html"),
      open: "never",
    }],
    ["json", {
      outputFile: resolve(evidenceRoot, "playwright-results.json"),
    }],
    ["./tests/e2e/support/releaseResultPolicyReporter.ts"],
  ],
  metadata: {
    e2eProfile: "performance-local-static",
    serverMode: "playwright-managed-static",
    exactInvocationOwnedProductionBytes: true,
    managedStaticBuildRoot: releaseBuildRoot,
    performanceEvidenceRoot: evidenceRoot,
    sourceBaselinePath: resolve(
      E2E_DATA_ROOT,
      `performance-source-${E2E_RUN_ID}.json`,
    ),
    releaseCandidateEligible: false,
    releaseBlockers: [
      "The current source and built bytes have not been independently attested as an immutable release candidate.",
      "Performance evidence does not replace interaction, visual, accessibility, soak, preview acceptance, or human sign-off.",
    ],
  },
  use: {
    baseURL,
    storageState: E2E_AUTH_STATE,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "light",
    contextOptions: { reducedMotion: "no-preference" },
    serviceWorkers: "allow",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "bun run scripts/start-managed-e2e-static-server.ts",
    url: new URL("/api/v2/health", baseURL).toString(),
    timeout: 120_000,
    reuseExistingServer: false,
    env: managedWebServerEnvironment({
      TI_SCALE_HOST: bind,
      TI_SCALE_PORT: port,
      TI_SCALE_SERVE_STATIC: "true",
      TI_SCALE_PREVIEW: "true",
      TI_SCALE_UI_ORIGIN: base.origin,
      TI_SCALE_DATABASE_PATH: E2E_DATABASE_PATH,
      TI_SCALE_PROVIDER_CONFIG_ROOT: E2E_PROVIDER_CONFIG_ROOT,
      TI_SCALE_SCRIPT_SOURCE_ROOT: E2E_SCRIPT_SOURCE_ROOT,
      TI_SCALE_DIST_ROOT: releaseBuildRoot,
      TI_SCALE_E2E_STATIC_BUILD_ID: managedStaticBuildId,
      TI_SCALE_OPERATOR_TOKEN_FILE: managedOperatorTokenFile,
      TI_SCALE_OPERATOR_ID: "e2e-local-operator",
      TI_SCALE_PERFORMANCE_BUILD: "true",
      TI_SCALE_VAULT_ROOT: E2E_VAULT_ROOT,
      TI_SCALE_E2E_RUN_ID: E2E_RUN_ID,
      TI_SCALE_TEST_RUN_CONTROL_RUNTIME: "true",
      TI_SCALE_TEST_RUN_CONTROL_SCHEDULER: "false",
      TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE:
        managedResearchIntegrityKeyFile,
      TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
    }),
  },
  projects: [{
    name: "performance-chromium",
    use: {
      browserName: "chromium",
      viewport: { width: 1440, height: 900 },
    },
  }],
});

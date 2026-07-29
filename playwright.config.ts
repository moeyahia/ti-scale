import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";
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
import { parseE2EProfile } from "./tests/e2e/support/e2eProfile";
import { managedWebServerEnvironment } from "./tests/e2e/support/managedWebServerEnvironment";
import { RELEASE_INTERACTION_PROJECT_ALLOWLIST } from "./tests/interaction-manifest/activationReceipts";
import { assertManagedE2EParentEnvironmentSafe } from "./scripts/managed-e2e-child-environment";

const root = import.meta.dirname;
const apiEntryExists = existsSync(resolve(root, "server/index.ts"));
const e2eProfile = parseE2EProfile();
const baseURL = e2eProfile.baseURL;
const apiURL = e2eProfile.apiURL;
const externalServers = e2eProfile.externalServers;
if (!externalServers) assertManagedE2EParentEnvironmentSafe(process.env);
if (!externalServers) {
  assertManagedE2EInvocationPaths();
}
const managedOperatorTokenFile = externalServers ? undefined : prepareManagedE2EOperatorTokenFile();
const managedResearchIntegrityKeyFile = externalServers
  ? undefined
  : prepareManagedE2EResearchIntegrityKeyFile();
const releaseProfile = e2eProfile.profile === "release";
const localUiServerUrl = new URL(baseURL);
const localApiServerUrl = new URL(apiURL);
const localUiBind = localUiServerUrl.hostname.replace(/^\[|\]$/gu, "") === "localhost"
  ? "127.0.0.1"
  : localUiServerUrl.hostname.replace(/^\[|\]$/gu, "");
const localApiBind = localApiServerUrl.hostname.replace(/^\[|\]$/gu, "") === "localhost"
  ? "127.0.0.1"
  : localApiServerUrl.hostname.replace(/^\[|\]$/gu, "");
const localUiPort = localUiServerUrl.port || (localUiServerUrl.protocol === "http:" ? "80" : "443");
const localApiPort = localApiServerUrl.port || (localApiServerUrl.protocol === "http:" ? "80" : "443");
const releaseServerUrl = new URL(baseURL);
const releaseBind = releaseServerUrl.hostname.replace(/^\[|\]$/gu, "") === "localhost"
  ? "127.0.0.1"
  : releaseServerUrl.hostname.replace(/^\[|\]$/gu, "");
const releasePort = releaseServerUrl.port || (releaseServerUrl.protocol === "http:" ? "80" : "443");
const evidenceRunId = E2E_RUN_ID.replace(/[^A-Za-z0-9._-]+/gu, "-").slice(0, 120) || "unnamed-run";
// WebGL implementation and forced Canvas fallback are renderer-specific
// contracts, not cross-browser behavior claims. Standard projects exclude
// their explicit tag; one dedicated Chromium project selects them. This keeps
// the release matrix at zero skipped tests while still executing both paths.
const brainRendererTestTag = /@brain-renderer/u;
// A release-profile server must never serve the shared mutable `dist` tree.
// Build into one invocation-owned directory, serve those exact bytes directly,
// and let the owning managed-server launcher delete the directory at exit.
// Browser tests do not publish a production release or retain a prior copy.
const managedStaticBuildId = `e2e-${evidenceRunId.slice(0, 108)}-${process.pid}`;
const releaseBuildRoot = resolve(
  E2E_DATA_ROOT,
  `static-build-${managedStaticBuildId}`,
);
const profileMetadata = {
  e2eProfile: e2eProfile.profile,
  requireApi: e2eProfile.requireApi,
  enforceManifest: e2eProfile.enforceManifest,
  serverMode: e2eProfile.serverMode,
  candidateSha: process.env.TI_SCALE_E2E_CANDIDATE_SHA?.trim(),
  ...(e2eProfile.releaseAttestation ? { releaseAttestation: e2eProfile.releaseAttestation } : {}),
};

const viewports = {
  phone360: { width: 360, height: 800 },
  phone390: { width: 390, height: 844 },
  tablet: { width: 768, height: 1024 },
  compactDesktop: { width: 1024, height: 768 },
  laptop: { width: 1280, height: 800 },
  desktop: { width: 1440, height: 900 },
  fullHd: { width: 1920, height: 1080 },
  wide: { width: 2560, height: 1440 },
  // A 1440×900 desktop at 200% browser zoom exposes a 720×450 CSS
  // viewport while rasterizing each CSS pixel at 2×2 device pixels. Chromium
  // headless does not honor Ctrl/Cmd-Plus as browser chrome does, so this
  // project emulates the resulting rendering geometry explicitly instead of
  // mislabeling a small 1x viewport as a native browser-zoom operation.
  zoom200CssViewport: { width: 720, height: 450 },
} as const;

export default defineConfig({
  testDir: "./tests/e2e",
  // This proof reads an already-populated operator deployment on loopback
  // port 3132. It has its own external-server-only configuration and must
  // never run against this managed invocation's disposable database/Vault.
  // Keeping the file in the audited browser inventory while excluding it
  // here preserves test-policy coverage without fabricating live state.
  testIgnore: [
    "live-readonly-3132.spec.ts",
    "live-autonomous-3132.spec.ts",
  ],
  globalSetup: "./tests/e2e/globalSetup.ts",
  globalTeardown: "./tests/e2e/globalTeardown.ts",
  outputDir: `./test-results/playwright/${evidenceRunId}`,
  fullyParallel: !releaseProfile,
  forbidOnly: true,
  retries: 0,
  workers: releaseProfile ? 1 : process.env.CI ? 2 : undefined,
  timeout: 30_000,
  expect: { timeout: 7_500 },
  reporter: [
    ["line"],
    ["html", { outputFolder: `test-results/html/${evidenceRunId}`, open: "never" }],
    ["json", { outputFile: `test-results/results/${evidenceRunId}.json` }],
    ["./tests/e2e/support/releaseResultPolicyReporter.ts"],
    ["./tests/e2e/support/interactionActivationReporter.ts", {
      outputFile: `test-results/results/${evidenceRunId}.interaction-activation-receipts.json`,
      enforce: process.env.TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS === "1",
      requiredProjects: RELEASE_INTERACTION_PROJECT_ALLOWLIST,
    }],
  ],
  use: {
    baseURL,
    storageState: E2E_AUTH_STATE,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "light",
    contextOptions: { reducedMotion: "no-preference" },
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
    serviceWorkers: "allow",
  },
  metadata: profileMetadata,
  webServer: externalServers ? undefined : releaseProfile ? {
    command: "bun run scripts/start-managed-e2e-static-server.ts",
    url: new URL("/api/v2/health", baseURL).toString(),
    timeout: 120_000,
    reuseExistingServer: false,
    env: managedWebServerEnvironment({
      TI_SCALE_HOST: releaseBind,
      TI_SCALE_PORT: releasePort,
      TI_SCALE_SERVE_STATIC: "true",
      TI_SCALE_PREVIEW: "true",
      TI_SCALE_UI_ORIGIN: releaseServerUrl.origin,
      TI_SCALE_DATABASE_PATH: E2E_DATABASE_PATH,
      TI_SCALE_PROVIDER_CONFIG_ROOT: E2E_PROVIDER_CONFIG_ROOT,
      TI_SCALE_SCRIPT_SOURCE_ROOT: E2E_SCRIPT_SOURCE_ROOT,
      TI_SCALE_DIST_ROOT: releaseBuildRoot,
      TI_SCALE_E2E_STATIC_BUILD_ID: managedStaticBuildId,
      TI_SCALE_OPERATOR_TOKEN_FILE: managedOperatorTokenFile,
      TI_SCALE_OPERATOR_ID: "e2e-local-operator",
      TI_SCALE_VAULT_ROOT: E2E_VAULT_ROOT,
      TI_SCALE_E2E_RUN_ID: E2E_RUN_ID,
      TI_SCALE_TEST_RUN_CONTROL_RUNTIME: "true",
      TI_SCALE_TEST_RUN_CONTROL_SCHEDULER: "false",
      TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE:
        managedResearchIntegrityKeyFile,
      TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
    }),
  } : [
    ...(apiEntryExists ? [{
      command: "bun run scripts/start-managed-e2e-api-server.ts",
      url: `${apiURL}/api/v2/health`,
      timeout: 120_000,
      // Every invocation owns a unique database, operator fixture, Vault root,
      // and evidence namespace. Reusing an orphaned local server can bind the
      // browser to a prior run's database while fixture helpers write to the
      // current one, producing hangs and false route/recovery results. Fail on
      // an occupied port instead of silently crossing that isolation boundary.
      reuseExistingServer: false,
      env: managedWebServerEnvironment({
        TI_SCALE_HOST: localApiBind,
        TI_SCALE_PORT: localApiPort,
        TI_SCALE_SERVE_STATIC: "false",
        TI_SCALE_DATABASE_PATH: E2E_DATABASE_PATH,
        TI_SCALE_PROVIDER_CONFIG_ROOT: E2E_PROVIDER_CONFIG_ROOT,
        TI_SCALE_SCRIPT_SOURCE_ROOT: E2E_SCRIPT_SOURCE_ROOT,
        TI_SCALE_OPERATOR_TOKEN_FILE: managedOperatorTokenFile,
        TI_SCALE_OPERATOR_ID: "e2e-local-operator",
        TI_SCALE_VAULT_ROOT: E2E_VAULT_ROOT,
        TI_SCALE_E2E_RUN_ID: E2E_RUN_ID,
        // Exposes only pause/resume/cancel against disposable Playwright
        // state. Planning, tool execution, and provider/MCP paths remain
        // fail-closed and are not mounted by this test-only boundary.
        TI_SCALE_TEST_RUN_CONTROL_RUNTIME: "true",
        // Browser suites exercise the HTTP adapter, not background execution.
        // Restart/recovery integration tests opt into the scheduler separately.
        TI_SCALE_TEST_RUN_CONTROL_SCHEDULER: "false",
        TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE:
          managedResearchIntegrityKeyFile,
        // Database-only fixture specialists are intentionally absent from the
        // standalone runtime manifest. Keep the real projector enabled while
        // preventing its normal 15-second reconciliation from racing an
        // isolated browser fixture during one bounded test invocation.
        TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
      }),
    }] : []),
    {
      command: "bun run scripts/start-managed-e2e-vite-server.ts",
      url: baseURL,
      timeout: 120_000,
      reuseExistingServer: false,
      env: managedWebServerEnvironment({
        TI_SCALE_API_ORIGIN: localApiServerUrl.origin,
        TI_SCALE_E2E_UI_HOST: localUiBind,
        TI_SCALE_E2E_UI_PORT: localUiPort,
      }),
    },
  ],
  projects: [
    { name: "chromium-1440", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.desktop } },
    { name: "firefox-1440", grepInvert: brainRendererTestTag, use: { browserName: "firefox", viewport: viewports.desktop } },
    { name: "webkit-1440", grepInvert: brainRendererTestTag, use: { browserName: "webkit", viewport: viewports.desktop } },
    { name: "chromium-enterprise-1440", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.desktop, userAgent: "Ti-Scale-Enterprise-Compatibility/2.4 Chromium" } },
    { name: "android-chromium-390", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.phone390, isMobile: true, hasTouch: true, deviceScaleFactor: 2.75 } },
    { name: "iphone-webkit-390", grepInvert: brainRendererTestTag, use: { browserName: "webkit", viewport: viewports.phone390, isMobile: true, hasTouch: true, deviceScaleFactor: 3 } },
    { name: "tablet-chromium-768", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.tablet, isMobile: true, hasTouch: true, deviceScaleFactor: 2 } },
    { name: "chromium-360", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.phone360, isMobile: true, hasTouch: true, deviceScaleFactor: 2 } },
    { name: "chromium-1024", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.compactDesktop } },
    { name: "chromium-1280", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.laptop } },
    { name: "chromium-1920", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.fullHd } },
    { name: "chromium-2560", grepInvert: brainRendererTestTag, use: { browserName: "chromium", viewport: viewports.wide } },
    {
      name: "chromium-200-percent-zoom",
      grepInvert: brainRendererTestTag,
      metadata: {
        ...profileMetadata,
        zoomContract: "1440x900 desktop rendered as a 720x450 CSS viewport at DPR 2",
        nativeBrowserChromeZoom: false,
      },
      use: {
        browserName: "chromium",
        viewport: viewports.zoom200CssViewport,
        deviceScaleFactor: 2,
        contextOptions: { reducedMotion: "no-preference", screen: viewports.desktop },
      },
    },
    {
      name: "brain-renderer-chromium-1440",
      grep: brainRendererTestTag,
      use: { browserName: "chromium", viewport: viewports.desktop },
    },
  ],
});

import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { E2E_AUTH_STATE, E2E_DATABASE_PATH, E2E_OPERATOR_TOKEN, E2E_RUN_ID, E2E_VAULT_ROOT } from "./tests/e2e/support/environment";
import { parseE2EProfile } from "./tests/e2e/support/e2eProfile";

const root = import.meta.dirname;
const apiEntryExists = existsSync(resolve(root, "server/index.ts"));
const e2eProfile = parseE2EProfile();
const baseURL = e2eProfile.baseURL;
const apiURL = e2eProfile.apiURL;
const externalServers = e2eProfile.externalServers;
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
// A release-profile server must never serve the shared mutable `dist` tree.
// Focused release gates can overlap while the full suite is still running;
// Vite clears its output directory at the start of each build, which used to
// make an already-running server return a transient document 500. Build into
// a process-owned directory, then use the same verified immutable handoff as
// preview/release deployments before the server starts.
const releaseStaticId = `e2e-${evidenceRunId.slice(0, 108)}-${process.pid}`;
const releaseStaticRoot = resolve(
  "/tmp/ti-scale-e2e-data",
  `static-releases-${evidenceRunId}`,
);
const releaseBuildRoot = resolve(
  "/tmp/ti-scale-e2e-data",
  `static-build-${releaseStaticId}`,
);
const profileMetadata = {
  e2eProfile: e2eProfile.profile,
  requireApi: e2eProfile.requireApi,
  enforceManifest: e2eProfile.enforceManifest,
  serverMode: e2eProfile.serverMode,
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
  globalSetup: "./tests/e2e/globalSetup.ts",
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
    command: [
      "bunx vite build --outDir \"$TI_SCALE_DIST_ROOT\" --emptyOutDir",
      "bun run release:static:stage",
      "bun run release:static:activate",
      "bun run server/index.ts",
    ].join(" && "),
    url: new URL("/api/v2/health", baseURL).toString(),
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      ...process.env,
      TI_SCALE_HOST: releaseBind,
      TI_SCALE_PORT: releasePort,
      TI_SCALE_SERVE_STATIC: "true",
      TI_SCALE_PREVIEW: "true",
      TI_SCALE_UI_ORIGIN: releaseServerUrl.origin,
      TI_SCALE_DATABASE_PATH: E2E_DATABASE_PATH,
      TI_SCALE_DIST_ROOT: releaseBuildRoot,
      TI_SCALE_STATIC_RELEASE_ID: releaseStaticId,
      TI_SCALE_STATIC_RELEASE_ROOT: releaseStaticRoot,
      TI_SCALE_OPERATOR_TOKEN: E2E_OPERATOR_TOKEN,
      TI_SCALE_OPERATOR_ID: "e2e-local-operator",
      TI_SCALE_VAULT_ROOT: E2E_VAULT_ROOT,
      TI_SCALE_E2E_RUN_ID: E2E_RUN_ID,
      TI_SCALE_TEST_RUN_CONTROL_RUNTIME: "true",
      TI_SCALE_TEST_RUN_CONTROL_SCHEDULER: "false",
      TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
    },
  } : [
    ...(apiEntryExists ? [{
      command: "bun run server/index.ts",
      url: `${apiURL}/api/v2/health`,
      timeout: 120_000,
      // Every invocation owns a unique database, operator fixture, Vault root,
      // and evidence namespace. Reusing an orphaned local server can bind the
      // browser to a prior run's database while fixture helpers write to the
      // current one, producing hangs and false route/recovery results. Fail on
      // an occupied port instead of silently crossing that isolation boundary.
      reuseExistingServer: false,
      env: {
        ...process.env,
        TI_SCALE_HOST: localApiBind,
        TI_SCALE_PORT: localApiPort,
        TI_SCALE_SERVE_STATIC: "false",
        TI_SCALE_DATABASE_PATH: E2E_DATABASE_PATH,
        TI_SCALE_OPERATOR_TOKEN: E2E_OPERATOR_TOKEN,
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
        // Database-only fixture specialists are intentionally absent from the
        // standalone runtime manifest. Keep the real projector enabled while
        // preventing its normal 15-second reconciliation from racing an
        // isolated browser fixture during one bounded test invocation.
        TI_SCALE_PROJECTION_INTERVAL_MS: "300000",
      },
    }] : []),
    {
      command: `CHOKIDAR_USEPOLLING=true CHOKIDAR_INTERVAL=1000 bunx vite --host ${localUiBind} --port ${localUiPort}`,
      url: baseURL,
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        ...process.env,
        TI_SCALE_API_ORIGIN: localApiServerUrl.origin,
      },
    },
  ],
  projects: [
    { name: "chromium-1440", use: { browserName: "chromium", viewport: viewports.desktop } },
    { name: "firefox-1440", use: { browserName: "firefox", viewport: viewports.desktop } },
    { name: "webkit-1440", use: { browserName: "webkit", viewport: viewports.desktop } },
    { name: "chromium-enterprise-1440", use: { browserName: "chromium", viewport: viewports.desktop, userAgent: "Ti-Scale-Enterprise-Compatibility/2.4 Chromium" } },
    { name: "android-chromium-390", use: { browserName: "chromium", viewport: viewports.phone390, isMobile: true, hasTouch: true, deviceScaleFactor: 2.75 } },
    { name: "iphone-webkit-390", use: { browserName: "webkit", viewport: viewports.phone390, isMobile: true, hasTouch: true, deviceScaleFactor: 3 } },
    { name: "tablet-chromium-768", use: { browserName: "chromium", viewport: viewports.tablet, isMobile: true, hasTouch: true, deviceScaleFactor: 2 } },
    { name: "chromium-360", use: { browserName: "chromium", viewport: viewports.phone360, isMobile: true, hasTouch: true, deviceScaleFactor: 2 } },
    { name: "chromium-1024", use: { browserName: "chromium", viewport: viewports.compactDesktop } },
    { name: "chromium-1280", use: { browserName: "chromium", viewport: viewports.laptop } },
    { name: "chromium-1920", use: { browserName: "chromium", viewport: viewports.fullHd } },
    { name: "chromium-2560", use: { browserName: "chromium", viewport: viewports.wide } },
    {
      name: "chromium-200-percent-zoom",
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
  ],
});

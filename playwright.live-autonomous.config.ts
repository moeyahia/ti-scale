import { defineConfig } from "@playwright/test";
import {
  E2E_AUTH_STATE,
  E2E_RUN_ID,
} from "./tests/e2e/support/environment";
import { parseE2EProfile } from "./tests/e2e/support/e2eProfile";

const profile = parseE2EProfile();
if (!profile.externalServers) {
  throw new Error(
    "The live Autonomous browser proof requires TI_SCALE_E2E_EXTERNAL_SERVERS=true",
  );
}

const baseURL = new URL(profile.baseURL);
const apiURL = new URL(profile.apiURL);
const isLoopback = (hostname: string): boolean =>
  hostname === "localhost"
  || hostname === "[::1]"
  || hostname === "::1"
  || /^127(?:\.\d{1,3}){3}$/u.test(hostname);

if (
  baseURL.protocol !== "http:"
  || apiURL.protocol !== "http:"
  || !isLoopback(baseURL.hostname)
  || !isLoopback(apiURL.hostname)
  || baseURL.origin !== apiURL.origin
  || baseURL.port !== "3132"
  || baseURL.username
  || baseURL.password
) {
  throw new Error(
    "The live Autonomous browser proof requires one credential-free loopback HTTP origin on port 3132",
  );
}

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "live-autonomous-3132.spec.ts",
  globalSetup: "./tests/e2e/live3132GlobalSetup.ts",
  globalTeardown: "./tests/e2e/live3132GlobalTeardown.ts",
  outputDir: `./test-results/playwright/live-autonomous-${E2E_RUN_ID}`,
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  timeout: 20 * 60_000,
  expect: { timeout: 20_000 },
  reporter: [
    ["line"],
    [
      "json",
      {
        outputFile:
          `test-results/results/live-autonomous-${E2E_RUN_ID}.json`,
      },
    ],
  ],
  metadata: {
    e2eProfile: "external-live-autonomous",
    externalServers: true,
    mutationPolicy:
      "one authorized disposable loopback Autonomous mission in the current Ti-Scale service",
    targetBoundary: "127.0.0.2 only",
    artifactCredentialPolicy:
      "operator-token value is never serialized; only an HttpOnly session is used",
  },
  use: {
    baseURL: baseURL.toString(),
    storageState: E2E_AUTH_STATE,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "light",
    viewport: { width: 1440, height: 900 },
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
    serviceWorkers: "allow",
  },
  projects: [{
    name: "live-autonomous-chromium-1440",
    use: { browserName: "chromium" },
  }],
  webServer: undefined,
});

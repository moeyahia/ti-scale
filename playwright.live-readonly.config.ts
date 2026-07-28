import { defineConfig } from "@playwright/test";
import { E2E_AUTH_STATE, E2E_RUN_ID } from "./tests/e2e/support/environment";
import { parseE2EProfile } from "./tests/e2e/support/e2eProfile";

const profile = parseE2EProfile();
if (!profile.externalServers) {
  throw new Error("The live read-only browser proof requires TI_SCALE_E2E_EXTERNAL_SERVERS=true");
}

const baseURL = new URL(profile.baseURL);
const apiURL = new URL(profile.apiURL);
const loopback = (hostname: string): boolean => hostname === "localhost"
  || hostname === "[::1]"
  || hostname === "::1"
  || /^127(?:\.\d{1,3}){3}$/u.test(hostname);
if (
  baseURL.protocol !== "http:"
  || apiURL.protocol !== "http:"
  || !loopback(baseURL.hostname)
  || !loopback(apiURL.hostname)
  || baseURL.origin !== apiURL.origin
  || baseURL.port !== "3132"
  || baseURL.username
  || baseURL.password
) {
  throw new Error("The live read-only browser proof requires one credential-free loopback HTTP origin on port 3132");
}

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "live-readonly-3132.spec.ts",
  globalSetup: "./tests/e2e/globalSetup.ts",
  outputDir: `./test-results/playwright/live-readonly-${E2E_RUN_ID}`,
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [
    ["line"],
    ["json", { outputFile: `test-results/results/live-readonly-${E2E_RUN_ID}.json` }],
  ],
  metadata: {
    e2eProfile: "external-live-read-only",
    externalServers: true,
    mutationPolicy: "blocked-in-browser-and-forbidden-by-spec",
    artifactCredentialPolicy: "operator-token-value-never-serialized",
  },
  use: {
    baseURL: baseURL.toString(),
    storageState: E2E_AUTH_STATE,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "light",
    viewport: { width: 1440, height: 900 },
    screenshot: "off",
    trace: "off",
    video: "off",
    serviceWorkers: "allow",
  },
  projects: [{ name: "live-readonly-chromium-1440", use: { browserName: "chromium" } }],
  webServer: undefined,
});

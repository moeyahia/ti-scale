import type { PlaywrightTestConfig } from "@playwright/test";

const module = await import("../playwright.config");
const config = module.default as PlaywrightTestConfig;
const violations: string[] = [];
const projectNames = config.projects?.map((project) => project.name) ?? [];
const expectedProjects = [
  "chromium-1440",
  "firefox-1440",
  "webkit-1440",
  "chromium-enterprise-1440",
  "android-chromium-390",
  "iphone-webkit-390",
  "tablet-chromium-768",
  "chromium-360",
  "chromium-1024",
  "chromium-1280",
  "chromium-1920",
  "chromium-2560",
  "chromium-200-percent-zoom",
  "brain-renderer-chromium-1440",
] as const;

if (JSON.stringify(projectNames) !== JSON.stringify(expectedProjects)) {
  violations.push(
    `project matrix differs: received ${projectNames.join(", ")}`,
  );
}
if (config.retries !== 0) violations.push("retries must equal zero");
if (config.forbidOnly !== true) violations.push("forbidOnly must be true");
if (config.workers !== 1) violations.push("release workers must equal one");
if (
  config.metadata?.candidateSha !== process.env.TI_SCALE_E2E_CANDIDATE_SHA
) {
  violations.push("resolved release metadata is not bound to the exact candidate SHA");
}
if (!config.webServer || Array.isArray(config.webServer)) {
  violations.push("release profile must resolve one managed static web server");
}
const reporters = config.reporter;
const reporterNames = typeof reporters === "string"
  ? [reporters]
  : (reporters ?? []).map((entry) => entry[0]);
for (const required of [
  "./tests/e2e/support/releaseResultPolicyReporter.ts",
  "./tests/e2e/support/interactionActivationReporter.ts",
]) {
  if (!reporterNames.includes(required)) {
    violations.push(`release reporter is missing ${required}`);
  }
}

if (violations.length > 0) {
  throw new Error(`Resolved Playwright release configuration failed:\n- ${violations.join("\n- ")}`);
}
console.log(
  `Resolved Playwright release configuration verified: ${String(projectNames.length)} `
    + "projects, one managed static server, one worker, zero retries",
);

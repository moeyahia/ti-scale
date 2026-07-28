import {
  readdirSync,
  readFileSync,
} from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const workflowRoot = resolve(root, ".github/workflows");
const reviewedWorkflows = Object.freeze([
  "ci.yml",
  "playwright-release.yml",
] as const);
const checkoutAction =
  "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
const setupBunAction =
  "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6";
const reviewedActions = new Set([checkoutAction, setupBunAction]);
const requiredProjects = Object.freeze([
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
] as const);

type Mapping = Readonly<Record<string, unknown>>;

function mapping(value: unknown, context: string): Mapping {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${context} must be a mapping`);
  }
  return value as Mapping;
}

function sequence(value: unknown, context: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${context} must be a sequence`);
  return value;
}

function scalar(value: unknown, context: string): string {
  if (typeof value !== "string") throw new Error(`${context} must be a string`);
  return value;
}

const violations: string[] = [];
const presentWorkflowFiles = readdirSync(workflowRoot)
  .filter((name) => /\.ya?ml$/u.test(name))
  .sort();
if (JSON.stringify(presentWorkflowFiles) !== JSON.stringify([...reviewedWorkflows].sort())) {
  violations.push(
    `workflow inventory must be exactly ${reviewedWorkflows.join(", ")}; received `
      + presentWorkflowFiles.join(", "),
  );
}

const parsed = new Map<string, Mapping>();
for (const name of reviewedWorkflows) {
  const path = resolve(workflowRoot, name);
  const document = mapping(
    Bun.YAML.parse(readFileSync(path, "utf8")),
    `${name} document`,
  );
  parsed.set(name, document);
  if (document.concurrency === undefined) {
    violations.push(`${name} must declare bounded concurrency`);
  }
  const permissions = mapping(document.permissions, `${name} permissions`);
  if (
    Object.keys(permissions).length !== 1
    || permissions.contents !== "read"
  ) {
    violations.push(`${name} permissions must be exactly contents: read`);
  }
  const jobs = mapping(document.jobs, `${name} jobs`);
  if (Object.keys(jobs).length === 0) violations.push(`${name} must declare a job`);
  for (const [jobName, unknownJob] of Object.entries(jobs)) {
    const job = mapping(unknownJob, `${name} job ${jobName}`);
    if (job.permissions !== undefined) {
      violations.push(`${name} job ${jobName} must not override top-level permissions`);
    }
    if (
      typeof job["timeout-minutes"] !== "number"
      || job["timeout-minutes"] <= 0
    ) {
      violations.push(`${name} job ${jobName} needs a positive timeout-minutes`);
    }
    const steps = sequence(job.steps, `${name} job ${jobName} steps`);
    let checkoutSeen = false;
    let bunSeen = false;
    let cleanupSeen = false;
    for (const [index, unknownStep] of steps.entries()) {
      const step = mapping(unknownStep, `${name} ${jobName} step ${String(index + 1)}`);
      if (step.uses !== undefined) {
        const action = scalar(step.uses, `${name} action`);
        if (!reviewedActions.has(action)) {
          violations.push(`${name} references unreviewed or mutable action ${action}`);
        }
        if (action === checkoutAction) {
          checkoutSeen = true;
          const options = mapping(step.with, `${name} checkout options`);
          if (options["persist-credentials"] !== false) {
            violations.push(`${name} checkout must set persist-credentials: false`);
          }
        }
        if (action === setupBunAction) {
          bunSeen = true;
          const options = mapping(step.with, `${name} Bun options`);
          if (options["bun-version"] !== "1.3.14") {
            violations.push(`${name} must pin Bun 1.3.14`);
          }
        }
      }
      if (step.if === "always()") cleanupSeen = true;
      if (typeof step.run === "string") {
        const lower = step.run.toLowerCase();
        for (const forbidden of [
          "actions/upload-artifact",
          "actions/download-artifact",
          "actions/cache",
          "docker build",
          "docker compose",
          "kubectl ",
          "helm ",
          " tar ",
          " zip ",
          " 7z ",
        ]) {
          if (lower.includes(forbidden)) {
            violations.push(`${name} run step contains forbidden ${forbidden.trim()}`);
          }
        }
      }
    }
    if (!checkoutSeen) violations.push(`${name} is missing the pinned checkout action`);
    if (!bunSeen) violations.push(`${name} is missing the pinned setup-bun action`);
    if (!cleanupSeen) violations.push(`${name} is missing unconditional transient cleanup`);
  }
}

const verification = parsed.get("ci.yml")!;
const verificationTriggers = mapping(verification.on, "ci.yml triggers");
for (const trigger of ["push", "pull_request", "workflow_dispatch"]) {
  if (!(trigger in verificationTriggers)) violations.push(`ci.yml is missing ${trigger}`);
}
const verificationJobs = mapping(verification.jobs, "ci.yml jobs");
const verificationJob = mapping(verificationJobs.verify, "ci.yml verify job");
const verificationEnvironment = mapping(
  verificationJob.env,
  "ci.yml verify environment",
);
if (verificationEnvironment.TI_SCALE_CANDIDATE_SHA !== "${{ github.sha }}") {
  violations.push("standalone verification must bind TI_SCALE_CANDIDATE_SHA to github.sha");
}
const verificationCommands = sequence(verificationJob.steps, "ci.yml verify steps")
  .map((value) => mapping(value, "ci.yml verify step").run)
  .filter((value): value is string => typeof value === "string")
  .join("\n");
for (const required of [
  "bun install --frozen-lockfile",
  "bun run scripts/validate-ci-workflows.ts",
  "bun run test:policy",
  "bun run isolation:verify",
  "bun run typecheck",
  "bun run typecheck:e2e",
  "bun run test",
  "bun run test:interaction-manifest",
  "bun run build",
  "bun run scripts/measure-bundle-performance.ts",
  "git rev-parse HEAD",
  "git status --porcelain=v1 --untracked-files=all",
]) {
  if (!verificationCommands.includes(required)) {
    violations.push(`standalone verification workflow is missing command ${required}`);
  }
}

const browser = parsed.get("playwright-release.yml")!;
const browserTriggers = mapping(browser.on, "playwright-release.yml triggers");
for (const trigger of [
  "push",
  "pull_request",
  "workflow_call",
  "workflow_dispatch",
  "schedule",
]) {
  if (!(trigger in browserTriggers)) {
    violations.push(`playwright-release.yml is missing ${trigger}`);
  }
}
const browserJobs = mapping(browser.jobs, "playwright-release.yml jobs");
const browserJob = mapping(browserJobs["full-browser-gate"], "full browser job");
const browserEnvironment = mapping(browserJob.env, "full browser environment");
for (const [name, expected] of Object.entries({
  TI_SCALE_E2E_PROFILE: "release",
  TI_SCALE_E2E_REQUIRE_API: "1",
  TI_SCALE_E2E_ENFORCE_MANIFEST: "1",
  TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS: "1",
  TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY: "1",
  TI_SCALE_E2E_SERVER_MODE: "playwright-managed-static",
  TI_SCALE_E2E_EXTERNAL_SERVERS: "false",
})) {
  if (browserEnvironment[name] !== expected) {
    violations.push(`full browser environment ${name} must equal ${expected}`);
  }
}
if (browserEnvironment.TI_SCALE_E2E_CANDIDATE_SHA !== "${{ github.sha }}") {
  violations.push("full browser gate must bind TI_SCALE_E2E_CANDIDATE_SHA to github.sha");
}

const browserStepRuns = sequence(browserJob.steps, "full browser steps")
  .map((value) => mapping(value, "full browser step").run)
  .filter((value): value is string => typeof value === "string");
const browserCommands = browserStepRuns.join("\n");
for (const required of [
  "bun install --frozen-lockfile",
  "bun run scripts/validate-ci-workflows.ts",
  "bun run scripts/validate-playwright-release-config.ts",
  "bun run isolation:verify",
  "bun run typecheck",
  "bun run typecheck:e2e",
  "bun run test",
  "bun run test:interaction-manifest",
  "bun run build",
  "bun run scripts/measure-bundle-performance.ts",
  "bun run scripts/report-browser-toolchain.ts",
  "playwright install --with-deps chromium firefox webkit",
  "bun run scripts/run-playwright-tests.ts",
  "--config=playwright.config.ts --retries=0",
  "git rev-parse HEAD",
]) {
  if (!browserCommands.includes(required)) {
    violations.push(`full browser workflow is missing command ${required}`);
  }
}
if (/--project(?:=|\s)/u.test(browserCommands)) {
  violations.push("full browser workflow must not filter the project matrix");
}
if (/(?:^|\s)--list(?:\s|$)/u.test(browserCommands)) {
  violations.push("full browser workflow must execute tests rather than list them");
}
if (
  (browserCommands.match(/git rev-parse HEAD/gu)?.length ?? 0) < 2
  || (
    browserCommands.match(
      /git status --porcelain=v1 --untracked-files=all/gu,
    )?.length ?? 0
  ) < 2
) {
  violations.push(
    "full browser workflow must prove exact candidate identity and a clean source tree before and after execution",
  );
}
if (
  (verificationCommands.match(/git rev-parse HEAD/gu)?.length ?? 0) < 2
  || (
    verificationCommands.match(
      /git status --porcelain=v1 --untracked-files=all/gu,
    )?.length ?? 0
  ) < 2
) {
  violations.push(
    "standalone verification must prove exact candidate identity and a clean source tree before and after execution",
  );
}

const playwright = readFileSync(resolve(root, "playwright.config.ts"), "utf8");
for (const project of requiredProjects) {
  if (!playwright.includes(`name: "${project}"`)) {
    violations.push(`Playwright config is missing ${project}`);
  }
}
for (const required of [
  "forbidOnly: true",
  "retries: 0",
  "workers: releaseProfile ? 1",
  "releaseResultPolicyReporter.ts",
]) {
  if (!playwright.includes(required)) {
    violations.push(`Playwright release policy is missing ${required}`);
  }
}

if (violations.length > 0) {
  throw new Error(`GitHub Actions policy validation failed:\n- ${violations.join("\n- ")}`);
}
console.log(
  `GitHub Actions policy verified structurally: ${String(requiredProjects.length)} `
    + "Playwright projects, immutable action SHAs, candidate-bound triggers, zero retries, "
    + "and no retained artifact action",
);

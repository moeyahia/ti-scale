#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

interface VisualBaselineRecord {
  readonly sourceFile: string;
  readonly testId: string;
  readonly carrierTitle: string;
  readonly project: string;
}

interface VisualBaselineRegistry {
  readonly baselines: readonly VisualBaselineRecord[];
}

const applicationRoot = resolve(import.meta.dir, "..");
const runner = resolve(applicationRoot, "scripts/run-playwright-tests.ts");
const registryPath = resolve(
  applicationRoot,
  "tests/interaction-manifest/visual-baselines.json",
);
if (!existsSync(runner) || !existsSync(registryPath)) {
  throw new Error("The visual-registry runner inputs are incomplete");
}
const bun = Bun.which("bun");
if (!bun) throw new Error("Bun is required to run the visual registry");

const registry = JSON.parse(
  readFileSync(registryPath, "utf8"),
) as VisualBaselineRegistry;
const carriers = [...new Map(
  registry.baselines.map((baseline) => [
    `${baseline.sourceFile}\u0000${baseline.carrierTitle}\u0000${baseline.project}`,
    Object.freeze({
      sourceFile: baseline.sourceFile,
      testId: baseline.testId,
      carrierTitle: baseline.carrierTitle,
      project: baseline.project,
    }),
  ]),
).values()];
if (carriers.length === 0) {
  throw new Error("The visual registry contains no carrier tests");
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

const failures: Array<Readonly<{
  sourceFile: string;
  testId: string;
  exitCode: number;
}>> = [];
for (let index = 0; index < carriers.length; index += 1) {
  const carrier = carriers[index]!;
  const runId = [
    "visual-registry",
    String(process.pid),
    String(index + 1),
    carrier.testId.replace(/[^A-Za-z0-9_-]+/gu, "-").slice(0, 80),
  ].join("-");
  process.stdout.write(
    `[visual-registry ${index + 1}/${carriers.length}] ${carrier.testId}\n`,
  );
  const child = Bun.spawn([
    bun,
    "run",
    runner,
    "--config=playwright.config.ts",
    `--project=${carrier.project}`,
    "--workers=1",
    "--retries=0",
    "--update-snapshots=none",
    carrier.sourceFile,
    "--grep",
    escapeRegularExpression(carrier.carrierTitle),
  ], {
    cwd: applicationRoot,
    env: {
      ...process.env,
      TI_SCALE_E2E_RUN_ID: runId,
      TI_SCALE_E2E_REQUIRE_API: "1",
      TI_SCALE_E2E_ENFORCE_MANIFEST: "0",
      TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS: "0",
      TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY: "1",
      TI_SCALE_E2E_EXTERNAL_SERVERS: "false",
    },
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  const exitCode = await child.exited;
  if (exitCode !== 0) failures.push({ ...carrier, exitCode });
}

if (failures.length > 0) {
  process.stderr.write(`${JSON.stringify({
    status: "failed",
    carrierCount: carriers.length,
    failedCount: failures.length,
    failures,
    snapshotsUpdated: false,
  }, null, 2)}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`${JSON.stringify({
    status: "passed",
    carrierCount: carriers.length,
    failedCount: 0,
    snapshotsUpdated: false,
    isolation: "one disposable database and server pair per carrier",
  }, null, 2)}\n`);
}

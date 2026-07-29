import { existsSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import {
  PERFORMANCE_SOURCE_PROVENANCE_SCHEMA,
  performanceEvidenceRunDirectory,
  performanceSourceBaselinePath,
  publishAtomicTextExclusive,
  reserveImmutableEvidenceDirectory,
  sourceTreeManifest,
  summarizeFileTree,
  type PerformanceSourceBaseline,
} from "../tests/performance/performanceProvenance";

const root = resolve(import.meta.dir, "..");
const runner = resolve(root, "scripts/run-playwright-tests.ts");
if (!existsSync(runner)) throw new Error("The reviewed Playwright runner is unavailable");
const e2eDataRoot = resolve("/tmp/ti-scale-e2e-data");

const runId = process.env.TI_SCALE_E2E_RUN_ID?.trim()
  || `web-vitals-${new Date().toISOString().replace(/[-:]/gu, "").replace(/\.\d{3}Z$/u, "Z")}`;
if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/u.test(runId)) {
  throw new Error("TI_SCALE_E2E_RUN_ID must be a safe evidence identifier");
}
const baseURL = process.env.TI_SCALE_E2E_BASE_URL?.trim()
  || "http://127.0.0.1:43880";
const apiURL = process.env.TI_SCALE_E2E_API_URL?.trim() || baseURL;
const evidenceRoot = performanceEvidenceRunDirectory(root, runId);
reserveImmutableEvidenceDirectory(evidenceRoot);
publishAtomicTextExclusive(
  resolve(evidenceRoot, "run-reservation.json"),
  `${JSON.stringify({
    schemaVersion: "ti-scale.performance-run-reservation.v1",
    runId,
    reservedAt: new Date().toISOString(),
    releaseCandidateEligible: false,
  }, null, 2)}\n`,
);
const sourceBaselinePath = performanceSourceBaselinePath(e2eDataRoot, runId);
const sourceBefore = summarizeFileTree(sourceTreeManifest(root));
const sourceBaseline: PerformanceSourceBaseline = Object.freeze({
  schemaVersion: PERFORMANCE_SOURCE_PROVENANCE_SCHEMA,
  runId,
  measuredAt: new Date().toISOString(),
  source: sourceBefore,
  launcher: Object.freeze({
    runtime: "bun",
    version: Bun.version,
  }),
});
publishAtomicTextExclusive(
  sourceBaselinePath,
  `${JSON.stringify(sourceBaseline, null, 2)}\n`,
);

let child: ReturnType<typeof Bun.spawn> | undefined;
let childExitCode = 1;
let childError: unknown;
const forward = (signal: "SIGINT" | "SIGTERM"): void => child?.kill(signal);
process.once("SIGINT", () => forward("SIGINT"));
process.once("SIGTERM", () => forward("SIGTERM"));
try {
  child = Bun.spawn([
    process.execPath,
    "run",
    runner,
    "--config=playwright.performance.config.ts",
    "--project=performance-chromium",
    "--workers=1",
    "--retries=0",
  ], {
    cwd: root,
    env: {
      ...process.env,
      TI_SCALE_E2E_RUN_ID: runId,
      TI_SCALE_E2E_BASE_URL: baseURL,
      TI_SCALE_E2E_API_URL: apiURL,
      TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY: "1",
    },
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  childExitCode = await child.exited;
} catch (error) {
  childError = error;
}

let sourceAfter: ReturnType<typeof summarizeFileTree> | undefined;
let sourceAfterError: string | undefined;
try {
  sourceAfter = summarizeFileTree(sourceTreeManifest(root));
} catch (error) {
  sourceAfterError = error instanceof Error ? error.message : String(error);
}
const sourceStable = sourceAfter !== undefined
  && sourceBefore.algorithm === sourceAfter.algorithm
  && sourceBefore.fileCount === sourceAfter.fileCount
  && sourceBefore.totalBytes === sourceAfter.totalBytes
  && sourceBefore.treeSha256 === sourceAfter.treeSha256;
const receipt = {
  schemaVersion: "ti-scale.performance-source-integrity.v1",
  runId,
  measuredAt: new Date().toISOString(),
  sourceBefore,
  sourceAfter: sourceAfter ?? null,
  sourceAfterError: sourceAfterError ?? null,
  sourceStable,
  childExitCode,
  childError: childError instanceof Error
    ? childError.message
    : childError === undefined
      ? null
      : String(childError),
  result: childExitCode === 0 && childError === undefined && sourceStable
    ? "pass"
    : "fail",
  releaseCandidateEligible: false,
};
try {
  publishAtomicTextExclusive(
    resolve(
      evidenceRoot,
      "source-integrity.json",
    ),
    `${JSON.stringify(receipt, null, 2)}\n`,
  );
} finally {
  rmSync(sourceBaselinePath, { force: true });
}
if (childError !== undefined) throw childError;
process.exitCode = childExitCode === 0 && sourceStable
  ? 0
  : childExitCode === 0
    ? 1
    : childExitCode;

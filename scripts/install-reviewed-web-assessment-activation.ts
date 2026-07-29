#!/usr/bin/env bun

import { resolve } from "node:path";
import {
  ReviewedWebAssessmentActivationInstaller,
  loadReviewedWebAssessmentActivationBundle,
} from "./release/ReviewedWebAssessmentActivationBundle";

const SOURCE_ROOT = resolve(import.meta.dir, "..");
const ID = "/usr/bin/id";

function serviceGid(): number {
  const result = Bun.spawnSync([ID, "-g", "ti-scale"], {
    cwd: "/",
    env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const gid = Number(result.stdout.toString().trim());
  if (result.exitCode !== 0 || !Number.isSafeInteger(gid) || gid < 1) {
    throw new Error("Could not resolve the Ti-Scale service group");
  }
  return gid;
}

function requireRoot(): void {
  if ((process.geteuid?.() ?? process.getuid?.() ?? -1) !== 0) {
    throw new Error("Installed activation verification and mutation require root");
  }
}

export type ReviewedWebAssessmentActivationCliOperation =
  | "source-verify"
  | "verify-installed";

export function reviewedWebAssessmentActivationUsage(): string {
  return [
    "Reviewed Ti-Scale web-assessment activation",
    "",
    `  bun run scripts/install-reviewed-web-assessment-activation.ts source-verify`,
    `  bun run scripts/install-reviewed-web-assessment-activation.ts verify-installed`,
    "",
    "Mutation is disabled by the operator no-backup policy.",
  ].join("\n");
}

export function parseReviewedWebAssessmentActivationArguments(
  args: readonly string[],
): Readonly<{
  readonly operation: ReviewedWebAssessmentActivationCliOperation;
  readonly mutates: boolean;
}> {
  const [operation, ...rest] = args;
  if (operation !== "source-verify" && operation !== "verify-installed") {
    throw new Error(reviewedWebAssessmentActivationUsage());
  }
  if (rest.length !== 0) {
    throw new Error(`${operation} accepts no additional arguments`);
  }
  return Object.freeze({ operation, mutates: false });
}

function main(): void {
  const { operation, mutates } = parseReviewedWebAssessmentActivationArguments(process.argv.slice(2));
  if (operation === "source-verify") {
    const prepared = loadReviewedWebAssessmentActivationBundle(SOURCE_ROOT);
    process.stdout.write(
      `source_verified: ${prepared.descriptor.bundleVersion}; service ${prepared.descriptor.serviceUnit}; no files installed\n`,
    );
    return;
  }
  requireRoot();
  if (mutates) {
    throw new Error("Activation CLI mutation classification failed closed");
  }
  const installer = new ReviewedWebAssessmentActivationInstaller({
    sourceRoot: SOURCE_ROOT,
    installedGroupGid: serviceGid(),
  });
  const result = installer.verifyPendingRestart();
  process.stdout.write(
    `${result.status}: ${result.bundleVersion}; service ${result.serviceUnit}; service restart performed=${result.serviceRestarted}\n`,
  );
}

if (import.meta.main) {
  try {
    main();
  } catch (error) {
    process.stderr.write(
      `Reviewed web-assessment activation failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
    );
    process.exitCode = 1;
  }
}

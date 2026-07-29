#!/usr/bin/env bun

import { createDatabaseConnection } from "../server/db";
import {
  parseReviewedRealCandidateLinuxActivationArguments,
  type ReviewedRealCandidateLinuxActivationArguments,
} from "./install-reviewed-real-candidate-linux-activation";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH,
  REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS,
  ReviewedRealCandidateLinuxActivationInstaller,
} from "./release/ReviewedRealCandidateLinuxActivationBundle";
import {
  BoundedReviewedCandidateActivationCommandPort,
  REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_CONFIRMATION,
  ReviewedCandidateLiveActivationVerifier,
  ReviewedRealCandidateLinuxForwardActivation,
} from "./release/ReviewedRealCandidateLinuxForwardActivation";
import {
  withCooperativeReleaseSignals,
  withSharedReleaseLock,
} from "./release/ReleaseExecutionBoundary";
import {
  queryActiveV2Work,
} from "./release/FunctionalReleasePrimitives";

export type ReviewedRealCandidateLinuxForwardActivationOperation =
  "inspect" | "activate";

export interface ReviewedRealCandidateLinuxForwardActivationArguments {
  readonly operation:
    ReviewedRealCandidateLinuxForwardActivationOperation;
  readonly execute: boolean;
  readonly confirmation?: string;
  readonly installer: ReviewedRealCandidateLinuxActivationArguments;
}

export function reviewedRealCandidateLinuxForwardActivationUsage(): string {
  return [
    "Ti-Scale reviewed real-candidate Linux forward activation",
    "",
    "Usage:",
    "  bun run scripts/activate-reviewed-real-candidate-linux.ts inspect [pins]",
    "  bun run scripts/activate-reviewed-real-candidate-linux.ts activate \\",
    `    --execute --confirmation ${REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_CONFIRMATION} [pins]`,
    "",
    "Pins are identical to candidate-linux:install-reviewed-real:",
    "  --bundle-version <stable-id>",
    `  --database-path ${REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH}`,
    "  --service-gid <positive-ti-scale-gid>",
    "  --source-trust-root <absolute-directory>",
    "  --profile-path <absolute-path> --profile-sha256 <sha256>",
    "  --adapter-path <absolute-path> --adapter-sha256 <sha256>",
    "  --procedure-path <absolute-path> --procedure-sha256 <sha256>",
    "  --broker-path <absolute-path> --broker-sha256 <sha256>",
    "  --register-path <absolute-path> --register-sha256 <sha256>",
    "",
    "inspect verifies source and exact installed-file identity without mutation.",
    "activate is idempotent and forward-only: exact install, exact registration,",
    "systemd reload, adapter/broker enable and ordered start, Ti-Scale restart,",
    "then live broker, health, readiness, and authenticated-session proof on",
    "http://127.0.0.1:3132.",
    "It refuses before publication when canonical Ti-Scale runs, leases, or",
    "database writers are active, and rechecks quiescence before systemd.",
    "",
    "No backup or rollback payload is created. No unrelated service is queried,",
    "stopped, restarted, enabled, or otherwise mutated.",
  ].join("\n");
}

export function parseReviewedRealCandidateLinuxForwardActivationArguments(
  argv: readonly string[],
): ReviewedRealCandidateLinuxForwardActivationArguments {
  const [operationValue, ...rest] = argv;
  if (operationValue !== "inspect" && operationValue !== "activate") {
    throw new Error(reviewedRealCandidateLinuxForwardActivationUsage());
  }
  let execute = false;
  let confirmation: string | undefined;
  const pins: string[] = [];
  for (let index = 0; index < rest.length; index += 1) {
    const value = rest[index]!;
    if (value === "--execute") {
      if (execute) throw new Error("--execute may appear only once");
      execute = true;
      continue;
    }
    if (value === "--confirmation") {
      if (confirmation !== undefined || !rest[index + 1]) {
        throw new Error("--confirmation requires one value");
      }
      confirmation = rest[index + 1]!;
      index += 1;
      continue;
    }
    pins.push(value);
  }
  if (
    operationValue === "activate"
    && (
      !execute
      || confirmation
        !== REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_CONFIRMATION
    )
  ) {
    throw new Error(
      `Activation requires --execute --confirmation ${REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_CONFIRMATION}`,
    );
  }
  if (
    operationValue === "inspect"
    && (execute || confirmation !== undefined)
  ) {
    throw new Error(
      "inspect is read-only and rejects --execute or --confirmation",
    );
  }
  const installer =
    parseReviewedRealCandidateLinuxActivationArguments([
      "verify-installed",
      ...pins,
    ]);
  return Object.freeze({
    operation: operationValue,
    execute,
    ...(confirmation ? { confirmation } : {}),
    installer,
  });
}

function requireRoot(): void {
  if ((process.geteuid?.() ?? process.getuid?.() ?? -1) !== 0) {
    throw new Error(
      "Reviewed candidate forward activation requires root",
    );
  }
}

async function main(): Promise<void> {
  if (process.argv.slice(2).includes("--help")) {
    process.stdout.write(
      `${reviewedRealCandidateLinuxForwardActivationUsage()}\n`,
    );
    return;
  }
  const args =
    parseReviewedRealCandidateLinuxForwardActivationArguments(
      process.argv.slice(2),
    );
  const database = createDatabaseConnection({
    filename: args.installer.databasePath,
    readonly: true,
    fileMustExist: true,
    busyTimeoutMs: 5_000,
    verifyIntegrity: false,
  });
  try {
    const installer =
      new ReviewedRealCandidateLinuxActivationInstaller({
        bundleVersion: args.installer.bundleVersion,
        database,
        databasePath: args.installer.databasePath,
        serviceGid: args.installer.serviceGid,
        source: args.installer.source,
      });
    const activation =
      new ReviewedRealCandidateLinuxForwardActivation({
        installer,
        commands: new BoundedReviewedCandidateActivationCommandPort(),
        verifier: new ReviewedCandidateLiveActivationVerifier({
          databasePath: args.installer.databasePath,
          paths: REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS,
        }),
        databasePath: args.installer.databasePath,
        paths: REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS,
        readActiveWork: () =>
          queryActiveV2Work(args.installer.databasePath),
      });
    if (args.operation === "inspect") {
      process.stdout.write(`${JSON.stringify(activation.inspect(), null, 2)}\n`);
      return;
    }
    requireRoot();
    const receipt = await withSharedReleaseLock(
      async () =>
        await withCooperativeReleaseSignals(
          async ({ signal }) => await activation.activate(signal),
        ),
      { operation: "reviewed-real-candidate-linux-forward-activation" },
    );
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `Reviewed candidate forward activation failed: ${
        error instanceof Error ? error.message : "unknown error"
      }\n`,
    );
    process.exitCode = 1;
  });
}

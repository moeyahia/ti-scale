#!/usr/bin/env bun

import { isAbsolute, resolve } from "node:path";
import { createDatabaseConnection } from "../server/db";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH,
  REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS,
  ReviewedRealCandidateLinuxActivationInstaller,
  type ReviewedRealCandidateLinuxSourceInput,
} from "./release/ReviewedRealCandidateLinuxActivationBundle";

const SHA256 = /^[a-f0-9]{64}$/u;
const OPERATIONS = Object.freeze([
  "source-verify",
  "install",
  "verify-installed",
] as const);

export type ReviewedRealCandidateLinuxActivationOperation =
  typeof OPERATIONS[number];

export interface ReviewedRealCandidateLinuxActivationArguments {
  readonly operation: ReviewedRealCandidateLinuxActivationOperation;
  readonly execute: boolean;
  readonly bundleVersion: string;
  readonly databasePath: string;
  readonly serviceGid: number;
  readonly source: ReviewedRealCandidateLinuxSourceInput;
}

export function reviewedRealCandidateLinuxActivationUsage(): string {
  return [
    "Ti-Scale reviewed real-candidate Linux activation file installer",
    "",
    "Usage:",
    "  bun run scripts/install-reviewed-real-candidate-linux-activation.ts source-verify [pins]",
    "  bun run scripts/install-reviewed-real-candidate-linux-activation.ts install --execute [pins]",
    "  bun run scripts/install-reviewed-real-candidate-linux-activation.ts verify-installed [pins]",
    "",
    "Required pins:",
    "  --bundle-version <stable-id>",
    "  --database-path <absolute-path>",
    "  --service-gid <positive-ti-scale-gid>",
    "  --source-trust-root <absolute-directory>",
    "  --profile-path <absolute-path> --profile-sha256 <sha256>",
    "  --adapter-path <absolute-path> --adapter-sha256 <sha256>",
    "  --broker-path <absolute-path> --broker-sha256 <sha256>",
    "  --register-path <absolute-path> --register-sha256 <sha256>",
    "",
    "The profile must pin the fixed production adapter and socket paths:",
    `  ${REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS.adapterExecutable}`,
    `  ${REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS.adapterSocket}`,
    "",
    "install is forward-only, creates no backup, refuses every existing",
    "destination, and never reloads, enables, starts, or restarts systemd.",
    "Registration and both live attestations remain separate explicit steps.",
  ].join("\n");
}

function required(
  values: ReadonlyMap<string, string>,
  name: string,
): string {
  const value = values.get(name)?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredAbsolute(
  values: ReadonlyMap<string, string>,
  name: string,
): string {
  const value = required(values, name);
  if (!isAbsolute(value)) throw new Error(`${name} must be absolute`);
  return resolve(value);
}

function requiredHash(
  values: ReadonlyMap<string, string>,
  name: string,
): string {
  const value = required(values, name);
  if (!SHA256.test(value)) {
    throw new Error(`${name} must be a lowercase SHA-256`);
  }
  return value;
}

export function parseReviewedRealCandidateLinuxActivationArguments(
  argv: readonly string[],
): ReviewedRealCandidateLinuxActivationArguments {
  const [operationValue, ...rest] = argv;
  if (
    !operationValue
    || !OPERATIONS.includes(
      operationValue as ReviewedRealCandidateLinuxActivationOperation,
    )
  ) {
    throw new Error(reviewedRealCandidateLinuxActivationUsage());
  }
  const operation =
    operationValue as ReviewedRealCandidateLinuxActivationOperation;
  const values = new Map<string, string>();
  let execute = false;
  const permitted = new Set([
    "--bundle-version",
    "--database-path",
    "--service-gid",
    "--source-trust-root",
    "--profile-path",
    "--profile-sha256",
    "--adapter-path",
    "--adapter-sha256",
    "--broker-path",
    "--broker-sha256",
    "--register-path",
    "--register-sha256",
  ]);
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index]!;
    if (argument === "--execute") {
      if (execute) throw new Error("--execute may appear only once");
      execute = true;
      continue;
    }
    if (
      !permitted.has(argument)
      || values.has(argument)
      || !rest[index + 1]
      || rest[index + 1]!.startsWith("--")
    ) {
      throw new Error(`Unsupported, duplicate, or missing argument: ${argument}`);
    }
    values.set(argument, rest[index + 1]!);
    index += 1;
  }
  if ((operation === "install") !== execute) {
    throw new Error(
      operation === "install"
        ? "Forward-only installation requires the explicit --execute flag"
        : "--execute is accepted only by install",
    );
  }
  const serviceGid = Number(required(values, "--service-gid"));
  if (!Number.isSafeInteger(serviceGid) || serviceGid < 1) {
    throw new Error("--service-gid must be a positive integer");
  }
  const databasePath = requiredAbsolute(values, "--database-path");
  if (
    databasePath !== REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH
  ) {
    throw new Error(
      `--database-path must equal ${REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH}`,
    );
  }
  return Object.freeze({
    operation,
    execute,
    bundleVersion: required(values, "--bundle-version"),
    databasePath,
    serviceGid,
    source: Object.freeze({
      trustRoot: requiredAbsolute(values, "--source-trust-root"),
      profilePath: requiredAbsolute(values, "--profile-path"),
      profileSha256: requiredHash(values, "--profile-sha256"),
      adapterExecutablePath: requiredAbsolute(values, "--adapter-path"),
      adapterExecutableSha256: requiredHash(values, "--adapter-sha256"),
      brokerExecutablePath: requiredAbsolute(values, "--broker-path"),
      brokerExecutableSha256: requiredHash(values, "--broker-sha256"),
      registerExecutablePath: requiredAbsolute(values, "--register-path"),
      registerExecutableSha256: requiredHash(values, "--register-sha256"),
    }),
  });
}

function requireRoot(): void {
  if ((process.geteuid?.() ?? process.getuid?.() ?? -1) !== 0) {
    throw new Error(
      "Installed activation verification and publication require root",
    );
  }
}

async function main(): Promise<void> {
  if (process.argv.slice(2).includes("--help")) {
    process.stdout.write(`${reviewedRealCandidateLinuxActivationUsage()}\n`);
    return;
  }
  const args = parseReviewedRealCandidateLinuxActivationArguments(
    process.argv.slice(2),
  );
  if (args.operation !== "source-verify") requireRoot();
  const database = createDatabaseConnection({
    filename: args.databasePath,
    readonly: true,
    fileMustExist: true,
    busyTimeoutMs: 5_000,
    verifyIntegrity: false,
  });
  try {
    const installer = new ReviewedRealCandidateLinuxActivationInstaller({
      bundleVersion: args.bundleVersion,
      database,
      databasePath: args.databasePath,
      serviceGid: args.serviceGid,
      source: args.source,
    });
    const receipt = args.operation === "install"
      ? installer.install()
      : args.operation === "verify-installed"
        ? installer.verifyInstalled()
        : installer.prepare().receipt;
    process.stdout.write(`${JSON.stringify({
      ...receipt,
      status: args.operation === "source-verify"
        ? "source_verified_not_installed"
        : receipt.status,
      operation: args.operation,
      nextRequiredAction: args.operation === "install"
        ? "Run the installed registration utility explicitly, start the adapter and broker explicitly, verify both live attestations, then restart Ti-Scale separately."
        : args.operation === "source-verify"
          ? "Review the receipt and rerun with install --execute only when publication is intended."
          : "Complete registration and both live attestations before projecting mission readiness.",
    }, null, 2)}\n`);
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `Reviewed real-candidate activation failed: ${
        error instanceof Error ? error.message : "unknown error"
      }\n`,
    );
    process.exitCode = 1;
  });
}

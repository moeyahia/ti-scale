#!/root/.bun/bin/bun
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { resolve, sep } from "node:path";
import { createDatabaseConnection } from "../server/db";
import {
  COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_BUNDLE_VERSION,
  prepareCompleteAutonomousCandidateActivationFixture,
} from "../server/autonomous-runtime/testing/CompleteAutonomousCandidateActivationFixture";
import {
  COMPLETE_AUTONOMOUS_CANDIDATE_GENERAL_EXTERNAL_TARGET_SUPPORT,
  COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET,
} from "../server/autonomous-runtime/testing/CompleteAutonomousCandidateProcedureProviderSource";

export const COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE =
  "/var/lib/ti-scale/data/ti-scale.sqlite" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_VAULT_SANDBOX =
  "/var/lib/ti-scale/vaults" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_SOURCE_ROOT =
  "/root/ti-scale/.artifacts/complete-autonomous-candidate-source-v1" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION =
  "I CONFIRM THE DISPOSABLE 127.0.0.2:8080 FIXTURE SEED WILL WRITE TO THE CANONICAL TI-SCALE DATABASE /var/lib/ti-scale/data/ti-scale.sqlite AND PROJECT SIX FIXTURE-ONLY NOTES TO THE CONNECTED OBSIDIAN VAULT; THIS DOES NOT ENABLE GENERAL HTB OR EXTERNAL-TARGET SUPPORT" as const;

const BUN = "/root/.bun/bin/bun";
const PROJECT_ROOT = "/root/ti-scale";
const ENTRIES = Object.freeze([
  Object.freeze({
    name: "adapter",
    entrypoint:
      "/root/ti-scale/server/autonomous-runtime/reviewed-real-candidate-linux-adapter-cli.ts",
    output: "reviewed-real-candidate-linux-adapter",
  }),
  Object.freeze({
    name: "broker",
    entrypoint:
      "/root/ti-scale/server/autonomous-runtime/reviewed-real-candidate-linux-broker-cli.ts",
    output: "reviewed-real-candidate-linux-broker",
  }),
  Object.freeze({
    name: "register",
    entrypoint:
      "/root/ti-scale/server/autonomous-runtime/reviewed-real-candidate-linux-register-cli.ts",
    output: "reviewed-real-candidate-linux-register",
  }),
] as const);

export interface CompleteAutonomousCandidatePreparationArguments {
  readonly execute: true;
  readonly confirmation:
    typeof COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION;
  readonly databasePath:
    typeof COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE;
  readonly vaultSandboxRoot:
    typeof COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_VAULT_SANDBOX;
  readonly sourceRoot: typeof COMPLETE_AUTONOMOUS_CANDIDATE_SOURCE_ROOT;
}

export function completeAutonomousCandidatePreparationUsage(): string {
  return [
    "Usage:",
    "  bun scripts/prepare-complete-autonomous-candidate-activation.ts \\",
    "    --execute --confirm-fixture-seed \\",
    `    '${COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION}'`,
    "",
    "Fixture-only forward preparation:",
    `  database: ${COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE}`,
    `  Vault sandbox: ${COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_VAULT_SANDBOX}`,
    `  immutable source root: ${COMPLETE_AUTONOMOUS_CANDIDATE_SOURCE_ROOT}`,
    `  only supported target: ${COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET}`,
    "  general HTB/external-target support: false",
    "",
    "This command creates no backup, installs nothing, registers nothing,",
    "does not reload systemd, does not start a service, and does not restart",
    "or deploy Ti-Scale. It writes a visibly labeled disposable fixture seed",
    "to the canonical production database and connected Vault. It refuses",
    "every alternate database, target, shortened acknowledgement, or",
    "general-capability interpretation.",
  ].join("\n");
}

export function parseCompleteAutonomousCandidatePreparationArguments(
  argv: readonly string[],
): CompleteAutonomousCandidatePreparationArguments {
  if (
    argv.length !== 3
    || argv[0] !== "--execute"
    || argv[1] !== "--confirm-fixture-seed"
    || argv[2] !== COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION
  ) {
    throw new Error(completeAutonomousCandidatePreparationUsage());
  }
  return Object.freeze({
    execute: true,
    confirmation:
      COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION,
    databasePath: COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE,
    vaultSandboxRoot:
      COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_VAULT_SANDBOX,
    sourceRoot: COMPLETE_AUTONOMOUS_CANDIDATE_SOURCE_ROOT,
  });
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertSourceRoot(): string {
  const root = resolve(COMPLETE_AUTONOMOUS_CANDIDATE_SOURCE_ROOT);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const metadata = lstatSync(root);
  if (
    root !== COMPLETE_AUTONOMOUS_CANDIDATE_SOURCE_ROOT
    || !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || realpathSync(root) !== root
    || metadata.uid !== 0
    || (metadata.mode & 0o077) !== 0
  ) {
    throw new Error(
      "Complete Autonomous candidate source root must be root-owned mode 0700",
    );
  }
  return root;
}

function assertCheckedInEntrypoint(path: string): void {
  const resolved = resolve(path);
  const metadata = lstatSync(resolved);
  if (
    !resolved.startsWith(`${PROJECT_ROOT}${sep}`)
    || !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.uid !== 0
    || (metadata.mode & 0o022) !== 0
  ) {
    throw new Error(
      `Checked-in activation entrypoint is not root-controlled: ${resolved}`,
    );
  }
}

function buildPinnedExecutable(
  root: string,
  entry: typeof ENTRIES[number],
): { readonly path: string; readonly sha256: string } {
  assertCheckedInEntrypoint(entry.entrypoint);
  const destination = resolve(root, entry.output);
  const candidate = resolve(root, `.${entry.output}.candidate`);
  if (
    !destination.startsWith(`${root}${sep}`)
    || !candidate.startsWith(`${root}${sep}`)
  ) {
    throw new Error("Compiled activation source escaped its trust root");
  }
  if (existsSync(candidate)) unlinkSync(candidate);
  const built = spawnSync(BUN, [
    "build",
    "--compile",
    "--no-compile-autoload-dotenv",
    "--no-compile-autoload-bunfig",
    "--no-compile-autoload-tsconfig",
    "--no-compile-autoload-package-json",
    `--outfile=${candidate}`,
    entry.entrypoint,
  ], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    maxBuffer: 4 * 1_024 * 1_024,
    env: {
      HOME: "/root",
      PATH: "/root/.bun/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    },
  });
  if (built.status !== 0 || !existsSync(candidate)) {
    if (existsSync(candidate)) unlinkSync(candidate);
    throw new Error(
      `Failed to compile ${entry.name}: ${(built.stderr || built.stdout).trim().slice(0, 2_000)}`,
    );
  }
  chmodSync(candidate, 0o700);
  const candidateBytes = readFileSync(candidate);
  const candidateSha256 = sha256(candidateBytes);
  if (existsSync(destination)) {
    const metadata = lstatSync(destination);
    const currentSha256 = metadata.isFile() && !metadata.isSymbolicLink()
      ? sha256(readFileSync(destination))
      : "";
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.uid !== 0
      || (metadata.mode & 0o777) !== 0o700
      || currentSha256 !== candidateSha256
    ) {
      unlinkSync(candidate);
      throw new Error(
        `Existing ${entry.name} source differs from the current deterministic build; no file was replaced`,
      );
    }
    unlinkSync(candidate);
  } else {
    renameSync(candidate, destination);
    chmodSync(destination, 0o700);
  }
  const final = lstatSync(destination);
  if (
    !final.isFile()
    || final.isSymbolicLink()
    || final.uid !== 0
    || (final.mode & 0o777) !== 0o700
    || sha256(readFileSync(destination)) !== candidateSha256
  ) {
    throw new Error(`${entry.name} source failed immutable build read-back`);
  }
  return Object.freeze({ path: destination, sha256: candidateSha256 });
}

export function prepareCompleteAutonomousCandidateActivation(
  authorization: CompleteAutonomousCandidatePreparationArguments,
): unknown {
  if (
    authorization.execute !== true
    || authorization.confirmation
      !== COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION
    || authorization.databasePath
      !== COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE
    || authorization.vaultSandboxRoot
      !== COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_VAULT_SANDBOX
    || authorization.sourceRoot
      !== COMPLETE_AUTONOMOUS_CANDIDATE_SOURCE_ROOT
  ) {
    throw new Error(completeAutonomousCandidatePreparationUsage());
  }
  const databasePath =
    COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE;
  const databaseMetadata = statSync(databasePath);
  if (
    !databaseMetadata.isFile()
    || databaseMetadata.uid < 1
    || databaseMetadata.gid < 1
  ) {
    throw new Error(
      "The canonical Ti-Scale database must identify the non-root service UID/GID",
    );
  }
  const root = assertSourceRoot();
  const builds = Object.fromEntries(
    ENTRIES.map((entry) => [entry.name, buildPinnedExecutable(root, entry)]),
  ) as Readonly<Record<
    typeof ENTRIES[number]["name"],
    { readonly path: string; readonly sha256: string }
  >>;
  const database = createDatabaseConnection({
    filename: databasePath,
    fileMustExist: true,
    busyTimeoutMs: 5_000,
    verifyIntegrity: false,
  });
  try {
    const receipt = prepareCompleteAutonomousCandidateActivationFixture({
      database,
      databasePath,
      vaultSandboxRoot:
        COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_VAULT_SANDBOX,
      activationSourceRoot: root,
      adapterPath: builds.adapter.path,
      adapterSha256: builds.adapter.sha256,
      brokerPath: builds.broker.path,
      brokerSha256: builds.broker.sha256,
      registerPath: builds.register.path,
      registerSha256: builds.register.sha256,
      serviceUid: databaseMetadata.uid,
      serviceGid: databaseMetadata.gid,
      bundleVersion:
        COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_BUNDLE_VERSION,
    });
    return Object.freeze({
      ...receipt,
      preparation: Object.freeze({
        explicitExecute: true,
        fixtureOnly: true,
        capabilityScope: "exact_disposable_fixture_only",
        supportedTarget:
          COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET,
        generalExternalTargetSupport:
          COMPLETE_AUTONOMOUS_CANDIDATE_GENERAL_EXTERNAL_TARGET_SUPPORT,
        generalMissionReadinessEligible: false,
        targetScopedReadinessRequired: true,
        confirmation:
          COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION,
        noBackupCreated: true,
        databasePath,
        databaseUid: databaseMetadata.uid,
        databaseGid: databaseMetadata.gid,
        vaultConnectionDiscovery:
          "unique_existing_connected_connection_under_exact_sandbox",
        compiledEntrypoints: Object.freeze(ENTRIES.map((entry) =>
          Object.freeze({
            name: entry.name,
            entrypoint: entry.entrypoint,
            sourcePath: builds[entry.name].path,
            sourceSha256: builds[entry.name].sha256,
          })
        )),
      }),
      nextRequiredAction:
        "This receipt proves only the disposable 127.0.0.2:8080 fixture. It does not establish general HTB or external-target support. Review sourceVerifyArguments before any separate fixture-only installation or registration. Service start/reload/restart remains a separate explicit operation.",
    });
  } finally {
    database.close();
  }
}

async function main(): Promise<void> {
  if (process.argv.slice(2).includes("--help")) {
    process.stdout.write(`${completeAutonomousCandidatePreparationUsage()}\n`);
    return;
  }
  const authorization = parseCompleteAutonomousCandidatePreparationArguments(
    process.argv.slice(2),
  );
  const receipt = prepareCompleteAutonomousCandidateActivation(authorization);
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `Complete Autonomous candidate fixture preparation failed: ${
        error instanceof Error ? error.message : "unknown error"
      }\n`,
    );
    process.exitCode = 1;
  });
}

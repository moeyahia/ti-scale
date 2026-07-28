#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  attestInstalledReleaseServiceStartAdmission,
  assertReleaseServiceStartAdmissionInstallationTargets,
  buildReleaseServiceStartAdmissionBundle,
  buildReleaseServiceWrapperBundle,
  RELEASE_SERVICE_START_ADMISSION_DROP_IN_PATH,
  RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND,
  RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
  RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT,
  RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND,
  RELEASE_SERVICE_WRAPPER_PATH,
  RELEASE_SERVICE_WRAPPER_USER,
  releaseServiceStartAdmissionSelfReportMatches,
  releaseServiceWrapperSelfReportMatches,
  serviceStartAdmissionConfigured,
  serviceStartAdmissionMountConfigured,
  serviceWrapperConfigured,
  serviceWrapperIdentityConfigured,
} from "./release/ReleaseServiceStartAdmissionBundle";
import { discoverIncompleteFunctionalReleaseTransactions } from "./release/DurableReleaseTransaction";
import {
  runBoundedReleaseCommand,
  runBoundedReleaseCommandSync,
} from "./release/BoundedReleaseCommand";
import { withSharedReleaseLock } from "./release/ReleaseExecutionBoundary";
import {
  assertReleaseServiceStartAdmissionJournalReadableByService,
  installReleaseServiceStartAdmissionWithActivation,
  RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME,
} from "./release/ReleaseServiceStartAdmissionInstallation";

const SOURCE_ROOT = resolve(import.meta.dir, "..");
const TRANSACTION_ROOT = RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT;
const DROP_IN_SOURCE = resolve(
  SOURCE_ROOT,
  "deployment/systemd/ti-scale.service.d/10-release-start-admission.conf",
);
const CONFIRMATION = "INSTALL_TI_SCALE_RELEASE_START_ADMISSION";

interface InstallerArguments {
  readonly execute: boolean;
  readonly confirmation?: string;
}

function parseArguments(argv: readonly string[]): InstallerArguments {
  let execute = false;
  let confirmation: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index]!;
    if (value === "--execute") execute = true;
    else if (value === "--confirmation") confirmation = argv[++index];
    else if (value === "--help") {
      process.stdout.write(
        `Usage: bun run scripts/install-release-start-admission.ts [--execute --confirmation ${CONFIRMATION}]\n`,
      );
      process.exit(0);
    } else throw new Error(`Unknown release-start admission installer argument: ${value}`);
  }
  if (execute && confirmation !== CONFIRMATION) {
    throw new Error(`Execution requires --confirmation ${CONFIRMATION}`);
  }
  return { execute, ...(confirmation ? { confirmation } : {}) };
}

async function effectiveConfiguration(): Promise<{
  readonly legacy: string;
  readonly extended: string;
  readonly startLegacy: string;
  readonly startExtended: string;
  readonly mounts: string;
  readonly user: string;
  readonly group: string;
  readonly workingDirectory: string;
  readonly dynamicUser: string;
}> {
  const legacy = await runBoundedReleaseCommand([
    "/usr/bin/systemctl", "show", "ti-scale.service", "--property=ExecStartPre", "--value",
  ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 });
  const extended = await runBoundedReleaseCommand([
    "/usr/bin/systemctl", "show", "ti-scale.service", "--property=ExecStartPreEx", "--value",
  ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 });
  const startLegacy = await runBoundedReleaseCommand([
    "/usr/bin/systemctl", "show", "ti-scale.service", "--property=ExecStart", "--value",
  ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 });
  const startExtended = await runBoundedReleaseCommand([
    "/usr/bin/systemctl", "show", "ti-scale.service", "--property=ExecStartEx", "--value",
  ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 });
  const mounts = await runBoundedReleaseCommand([
    "/usr/bin/systemctl", "show", "ti-scale.service", "--property=RequiresMountsFor", "--value",
  ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 });
  const identity = await Promise.all(["User", "Group", "WorkingDirectory", "DynamicUser"].map((property) =>
    runBoundedReleaseCommand([
      "/usr/bin/systemctl", "show", "ti-scale.service", `--property=${property}`, "--value",
    ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 })
  ));
  return {
    legacy: legacy.stdout,
    extended: extended.stdout,
    startLegacy: startLegacy.stdout,
    startExtended: startExtended.stdout,
    mounts: mounts.stdout,
    user: identity[0]!.stdout,
    group: identity[1]!.stdout,
    workingDirectory: identity[2]!.stdout,
    dynamicUser: identity[3]!.stdout,
  };
}

export async function installReleaseServiceStartAdmission(
  args: InstallerArguments,
): Promise<Readonly<Record<string, unknown>>> {
  const bundle = await buildReleaseServiceStartAdmissionBundle(SOURCE_ROOT);
  const wrapperBundle = await buildReleaseServiceWrapperBundle(SOURCE_ROOT);
  // Load and validate every source payload before the first privileged write.
  // The cached bytes are then the bytes installed and subsequently attested.
  const dropInBytes = readFileSync(DROP_IN_SOURCE);
  const dropInText = dropInBytes.toString("utf8");
  if (
    !dropInText.includes(`RequiresMountsFor=${TRANSACTION_ROOT}`) ||
    !dropInText.includes(`ExecStartPre=+${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND}`) ||
    !dropInText.includes("ExecStart=\n") ||
    !dropInText.includes(`ExecStart=${RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND}`)
  ) throw new Error("Reviewed release-start systemd drop-in source is incomplete or incompatible");
  if (!args.execute) {
    return Object.freeze({
      status: "dry_run",
      schemaVersion: bundle.schemaVersion,
      helperPath: RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
      helperSha256: bundle.sha256,
      wrapperPath: RELEASE_SERVICE_WRAPPER_PATH,
      wrapperSha256: wrapperBundle.sha256,
      dropInPath: RELEASE_SERVICE_START_ADMISSION_DROP_IN_PATH,
      installationJournal: resolve(
        RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT,
        RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME,
      ),
      effectiveCommand: RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND,
      serviceRestarted: false,
    });
  }
  if (process.getuid?.() !== 0) throw new Error("Release-start admission installation requires root");
  if (!existsSync(TRANSACTION_ROOT)) {
    throw new Error("Canonical release transaction root must exist before installing the startup gate");
  }

  return withSharedReleaseLock(async () => {
    const incomplete = discoverIncompleteFunctionalReleaseTransactions(TRANSACTION_ROOT);
    if (incomplete.length) {
      throw new Error("Release-start admission cannot be installed during a nonterminal release transaction");
    }
    assertReleaseServiceStartAdmissionInstallationTargets();
    const installationOptions = {
      transactionRoot: TRANSACTION_ROOT,
      trustedAncestorBoundary: "/",
      serviceUser: RELEASE_SERVICE_WRAPPER_USER,
      runServiceAccessCommand: (
        command: readonly string[],
        invocation: { readonly allowNonZeroExit: boolean },
      ) =>
        runBoundedReleaseCommandSync(command, {
          timeoutMs: 15_000,
          outputLimitBytes: 64 * 1_024,
          allowNonZeroExit: invocation.allowNonZeroExit,
        }),
    } as const;
    const installed = await installReleaseServiceStartAdmissionWithActivation({
      helperBytes: bundle.bytes,
      wrapperBytes: wrapperBundle.bytes,
      dropInBytes,
    }, async (activation) => {
      const journalPath = resolve(
        RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT,
        RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME,
      );
      await runBoundedReleaseCommand([
        "/usr/sbin/runuser",
        "--user",
        RELEASE_SERVICE_WRAPPER_USER,
        "--",
        "/usr/bin/test",
        "-r",
        journalPath,
      ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 });
      const attestation = await attestInstalledReleaseServiceStartAdmission({
        sourceRoot: SOURCE_ROOT,
      });
      await runBoundedReleaseCommand(
        ["/usr/bin/systemctl", "daemon-reload"],
        { timeoutMs: 30_000, outputLimitBytes: 64 * 1_024 },
      );
      activation.serviceManagerReloaded();
      const configured = await effectiveConfiguration();
      if (!serviceStartAdmissionConfigured(configured.legacy, configured.extended)) {
        throw new Error("Effective ti-scale.service ExecStartPre is not the exact guarded command");
      }
      if (!serviceWrapperConfigured(configured.startLegacy, configured.startExtended)) {
        throw new Error("Effective ti-scale.service ExecStart is not the exact unprivileged stable wrapper");
      }
      if (!serviceWrapperIdentityConfigured(
        configured.user,
        configured.group,
        configured.workingDirectory,
        configured.dynamicUser,
      )) {
        throw new Error("Effective ti-scale.service wrapper identity or working directory is unsafe");
      }
      if (!serviceStartAdmissionMountConfigured(configured.mounts)) {
        throw new Error("Effective ti-scale.service is missing the canonical release-journal mount dependency");
      }
      const selfReport = await runBoundedReleaseCommand([
        "/usr/local/bin/bun",
        "run",
        RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
        "--self-report",
      ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 });
      if (!releaseServiceStartAdmissionSelfReportMatches(selfReport.stdout)) {
        throw new Error("Installed release-start helper returned an incompatible protocol self-report");
      }
      const wrapperSelfReport = await runBoundedReleaseCommand([
        "/usr/sbin/runuser",
        "--user",
        RELEASE_SERVICE_WRAPPER_USER,
        "--",
        "/usr/local/bin/bun",
        "run",
        RELEASE_SERVICE_WRAPPER_PATH,
        "--self-report",
      ], { timeoutMs: 15_000, outputLimitBytes: 64 * 1_024 });
      if (!releaseServiceWrapperSelfReportMatches(wrapperSelfReport.stdout)) {
        throw new Error("Installed service wrapper returned an incompatible protocol self-report");
      }
      return Object.freeze({
        attestation,
        selfReport: JSON.parse(selfReport.stdout) as unknown,
        wrapperSelfReport: JSON.parse(wrapperSelfReport.stdout) as unknown,
      });
    }, installationOptions);
    assertReleaseServiceStartAdmissionJournalReadableByService(
      installationOptions,
    );
    return Object.freeze({
      status: "installed",
      ...installed.activation.attestation,
      installation: installed.installation,
      helperPath: RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
      wrapperPath: RELEASE_SERVICE_WRAPPER_PATH,
      dropInPath: RELEASE_SERVICE_START_ADMISSION_DROP_IN_PATH,
      effectiveCommand: RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND,
      selfReport: installed.activation.selfReport,
      wrapperSelfReport: installed.activation.wrapperSelfReport,
      serviceRestarted: false,
    });
  }, { operation: "install-release-start-admission" });
}

if (import.meta.main) {
  installReleaseServiceStartAdmission(parseArguments(process.argv.slice(2)))
    .then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`${JSON.stringify({
        status: "failed",
        message: error instanceof Error ? error.message : "Release-start admission installation failed",
      })}\n`);
      process.exitCode = 1;
    });
}

import { readFileSync, writeFileSync } from "node:fs";
import {
  installReleaseServiceStartAdmissionWithActivation,
  type ReleaseServiceStartAdmissionInPlaceWritePhase,
  type ReleaseServiceStartAdmissionInstalledArtifact,
  type ReleaseServiceStartAdmissionInstallationBoundary,
} from "../../../../scripts/release/ReleaseServiceStartAdmissionInstallation";
import { writeDurableFileAtomically } from
  "../../../../scripts/release/DurableAtomicFile";

interface WorkerConfiguration {
  readonly transactionRoot: string;
  readonly trustedAncestorBoundary: string;
  readonly helperPath: string;
  readonly wrapperPath: string;
  readonly dropInPath: string;
  readonly helperInputPath: string;
  readonly wrapperInputPath: string;
  readonly dropInInputPath: string;
  readonly resultPath: string;
  readonly reloadReceiptPath: string;
  readonly crashBoundary: ReleaseServiceStartAdmissionInstallationBoundary | "none";
  readonly crashWriteArtifact?: ReleaseServiceStartAdmissionInstalledArtifact | "none";
  readonly crashWritePhase?: ReleaseServiceStartAdmissionInPlaceWritePhase | "none";
  readonly expectedUid: number;
  readonly expectedGid: number;
  readonly umask?: number;
}

const configurationPath = process.argv[2];
if (!configurationPath) throw new Error("Installation worker requires a configuration path");
const configuration = JSON.parse(
  readFileSync(configurationPath, "utf8"),
) as WorkerConfiguration;
if (configuration.umask !== undefined) process.umask(configuration.umask);

const result = await installReleaseServiceStartAdmissionWithActivation({
  helperBytes: readFileSync(configuration.helperInputPath),
  wrapperBytes: readFileSync(configuration.wrapperInputPath),
  dropInBytes: readFileSync(configuration.dropInInputPath),
}, async (activation) => {
  writeDurableFileAtomically(
    configuration.reloadReceiptPath,
    `${JSON.stringify({ status: "reloaded", processId: process.pid })}\n`,
    { mode: 0o600 },
  );
  activation.serviceManagerReloaded();
  return Object.freeze({ status: "verified" });
}, {
  transactionRoot: configuration.transactionRoot,
  trustedAncestorBoundary: configuration.trustedAncestorBoundary,
  helperPath: configuration.helperPath,
  wrapperPath: configuration.wrapperPath,
  dropInPath: configuration.dropInPath,
  expectedUid: configuration.expectedUid,
  expectedGid: configuration.expectedGid,
  onBoundary: (boundary) => {
    if (boundary === configuration.crashBoundary) {
      process.kill(process.pid, "SIGKILL");
    }
  },
  onInPlaceWritePhase: (artifact, phase) => {
    if (
      artifact === configuration.crashWriteArtifact &&
      phase === configuration.crashWritePhase
    ) {
      process.kill(process.pid, "SIGKILL");
    }
  },
});

writeFileSync(configuration.resultPath, `${JSON.stringify(result.installation, null, 2)}\n`, {
  mode: 0o600,
});

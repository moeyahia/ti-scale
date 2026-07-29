import { realpathSync } from "node:fs";
import { isAbsolute } from "node:path";
import { createDatabaseConnection } from "../db";
import { notifySystemdServiceReady } from "../app/SystemdServiceReadiness";
import {
  RunScopedReviewedCandidateLinuxProcedureActivationBridge,
} from "./RunScopedReviewedCandidateLinuxProcedureActivation";
import {
  loadTrustedReviewedRealCandidateLinuxProfile,
  startReviewedRealCandidateLinuxAdapter,
} from "./ReviewedRealCandidateLinuxTransport";

const SHA256 = /^[a-f0-9]{64}$/u;

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function absolute(name: string): string {
  const value = required(name);
  if (!isAbsolute(value)) throw new Error(`${name} must be absolute`);
  return value;
}

function digest(name: string): string {
  const value = required(name);
  if (!SHA256.test(value)) {
    throw new Error(`${name} must be a lowercase SHA-256`);
  }
  return value;
}

const trustRoot = absolute("TI_SCALE_CANDIDATE_LINUX_TRUST_ROOT");
const loadedProfile = loadTrustedReviewedRealCandidateLinuxProfile({
  path: absolute("TI_SCALE_CANDIDATE_LINUX_PROFILE_PATH"),
  trustRoot,
  expectedSha256: digest("TI_SCALE_CANDIDATE_LINUX_PROFILE_SHA256"),
  allowedOwnerUids: [0],
  maximumBytes: 64 * 1_024,
});
const invokedEntrypoint = process.argv[1];
if (
  !invokedEntrypoint
  || realpathSync(invokedEntrypoint)
    !== realpathSync(loadedProfile.value.adapter.executablePath)
) {
  throw new Error(
    "The running reviewed real-candidate adapter entrypoint is not the executable pinned by the profile",
  );
}
const database = createDatabaseConnection({
  filename: absolute("TI_SCALE_DATABASE_PATH"),
  fileMustExist: true,
  busyTimeoutMs: 5_000,
  verifyIntegrity: false,
});
const implementation =
  new RunScopedReviewedCandidateLinuxProcedureActivationBridge({
    database,
    loadedProfile,
    procedureTrustRoot: absolute(
      "TI_SCALE_CANDIDATE_LINUX_PROCEDURE_TRUST_ROOT",
    ),
    adapterExecutableSha256:
      loadedProfile.value.adapter.executableSha256,
    allowedProcedureOwnerUids: [
      0,
      process.geteuid?.() ?? process.getuid?.() ?? 0,
    ],
  });
await implementation.attest(new AbortController().signal);
const adapter = await startReviewedRealCandidateLinuxAdapter({
  loadedProfile,
  implementation,
});
let closing = false;
async function close(): Promise<void> {
  if (closing) return;
  closing = true;
  try {
    await adapter.close();
  } finally {
    database.close();
  }
}

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    void close().then(
      () => process.exit(0),
      (error) => {
        process.stderr.write(
          `${error instanceof Error ? error.message : String(error)}\n`,
        );
        process.exit(1);
      },
    );
  });
}

try {
  notifySystemdServiceReady(
    "Reviewed candidate Linux adapter socket is ready",
  );
} catch (error) {
  await close();
  throw error;
}

process.stdout.write(`${JSON.stringify({
  status: "conditional_adapter_ready_pending_broker_attestation",
  candidateClass: "reviewed_real_candidate_v1",
  realTargetSupport: true,
  targetScope: loadedProfile.value.targetScope,
  bindingId: loadedProfile.value.bindingId,
  postExploitSpecId: loadedProfile.value.postExploitSpec.id,
  scriptArtifactId:
    loadedProfile.value.postExploitSpec.scriptArtifactId,
  exploitOutcomeObserverSpecId:
    loadedProfile.value.postExploitSpec.exploitOutcomeObserverSpecId,
  socketPath: adapter.socketPath,
  profileSha256: loadedProfile.receipt.sourceSha256,
  adapterExecutableSha256:
    loadedProfile.value.adapter.executableSha256,
  conditionalCapability: true,
  candidateProcedurePresentAtLaunch: true,
  procedureProviderPresentAtLaunch: true,
  runScopedProcedureActivationPresentAtLaunch: false,
  grantsRunDispatch: false,
  procedureTrustRoot: absolute(
    "TI_SCALE_CANDIDATE_LINUX_PROCEDURE_TRUST_ROOT",
  ),
  missionExecutionReady: false,
  nextRequiredAction:
    "Start the hash-pinned broker for launch readiness. The provider is installed, but candidate dispatch remains blocked until discovery produces an independently validated byte-identical ScriptArtifact, target-free provider admission, and exact run-scoped activation.",
})}\n`);

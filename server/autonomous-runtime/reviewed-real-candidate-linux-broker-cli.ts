import { isAbsolute } from "node:path";
import { realpathSync } from "node:fs";
import { createDatabaseConnection } from "../db";
import {
  CandidateLinuxTransportBindingRegistry,
  loadTrustedCandidateLinuxTransportBindingManifest,
} from "./CandidateLinuxTransportBindingRegistry";
import { startCandidateLinuxTransportBroker } from "./CandidateLinuxTransportBroker";
import {
  loadTrustedReviewedRealCandidateLinuxProfile,
  ReviewedRealCandidateLinuxTransportHandler,
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
const manifest = loadTrustedCandidateLinuxTransportBindingManifest({
  path: absolute("TI_SCALE_CANDIDATE_LINUX_MANIFEST_PATH"),
  trustRoot,
  expectedSha256: digest("TI_SCALE_CANDIDATE_LINUX_MANIFEST_SHA256"),
  allowedOwnerUids: [0],
  maximumBytes: 64 * 1_024,
});
const invokedEntrypoint = process.argv[1];
if (
  !invokedEntrypoint
  || realpathSync(invokedEntrypoint)
    !== realpathSync(manifest.value.broker.executablePath)
) {
  throw new Error(
    "The running reviewed real-candidate broker entrypoint is not the executable pinned by the manifest",
  );
}
if (
  manifest.value.bindings.some(
    (binding) =>
      binding.candidateClass !== "reviewed_real_candidate_v1"
      || binding.realTargetSupport !== true,
  )
) {
  throw new Error(
    "The production real-candidate broker accepts only reviewed_real_candidate_v1 bindings",
  );
}
const handlers = manifest.value.bindings.map((binding) =>
  new ReviewedRealCandidateLinuxTransportHandler({
    loadedProfile: loadTrustedReviewedRealCandidateLinuxProfile({
      path: binding.handlerProfilePath,
      trustRoot,
      expectedSha256: binding.handlerProfileSha256,
      allowedOwnerUids: [0],
      maximumBytes: 64 * 1_024,
    }),
    binding,
  }));
const database = createDatabaseConnection({
  filename: absolute("TI_SCALE_DATABASE_PATH"),
  readonly: true,
  fileMustExist: true,
  busyTimeoutMs: 5_000,
  verifyIntegrity: false,
});
const registry = new CandidateLinuxTransportBindingRegistry({
  database,
  loadedManifest: manifest,
});
const broker = await startCandidateLinuxTransportBroker({
  manifest: manifest.value,
  manifestSha256: manifest.receipt.sourceSha256,
  authorizer: registry,
  handlers,
});

let closing = false;
async function close(): Promise<void> {
  if (closing) return;
  closing = true;
  await broker.close();
  database.close();
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

process.stdout.write(`${JSON.stringify({
  status: "ready",
  candidateClass: "reviewed_real_candidate_v1",
  realTargetSupport: true,
  bindingIds: manifest.value.bindings.map(({ bindingId }) => bindingId),
  socketPath: broker.socketPath,
  manifestSha256: manifest.receipt.sourceSha256,
})}\n`);

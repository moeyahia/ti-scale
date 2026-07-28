import { isAbsolute } from "node:path";
import {
  createDatabaseConnection,
} from "../db";
import {
  loadTrustedCandidateLinuxTransportBindingManifest,
  CandidateLinuxTransportBindingRegistry,
} from "./CandidateLinuxTransportBindingRegistry";
import {
  startCandidateLinuxTransportBroker,
} from "./CandidateLinuxTransportBroker";
import {
  DisposableLocalCandidateLinuxTransportHandler,
  loadTrustedDisposableLocalCandidateLinuxProfile,
} from "./DisposableLocalCandidateLinuxTransport";

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
if (manifest.value.bindings.length !== 1) {
  throw new Error(
    "The disposable local broker requires exactly one pinned candidate binding",
  );
}
const binding = manifest.value.bindings[0]!;
const profile = loadTrustedDisposableLocalCandidateLinuxProfile({
  path: binding.handlerProfilePath,
  trustRoot,
  expectedSha256: binding.handlerProfileSha256,
  allowedOwnerUids: [0],
  maximumBytes: 32 * 1_024,
});
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
  handlers: [
    new DisposableLocalCandidateLinuxTransportHandler({
      loadedProfile: profile,
      binding,
      allowedProofFileOwnerUids: [0],
    }),
  ],
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

process.stdout.write(
  `${JSON.stringify({
    status: "ready",
    candidateClass: binding.candidateClass,
    realTargetSupport: binding.realTargetSupport,
    bindingId: binding.bindingId,
    socketPath: broker.socketPath,
    manifestSha256: manifest.receipt.sourceSha256,
  })}\n`,
);

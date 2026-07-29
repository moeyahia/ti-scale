import { isAbsolute } from "node:path";
import { createDatabaseConnection } from "../db";
import {
  loadTrustedCandidateLinuxTransportBindingManifest,
} from "./CandidateLinuxTransportBindingRegistry";
import {
  loadTrustedReviewedRealCandidateLinuxProfile,
  registerReviewedRealCandidateLinuxPostExploitSpec,
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
if (
  manifest.value.bindings.some(
    (binding) =>
      binding.candidateClass !== "reviewed_real_candidate_v1"
      || binding.realTargetSupport !== true,
  )
) {
  throw new Error(
    "Real-candidate registration accepts only reviewed_real_candidate_v1 bindings",
  );
}
const database = createDatabaseConnection({
  filename: absolute("TI_SCALE_DATABASE_PATH"),
  fileMustExist: true,
  busyTimeoutMs: 5_000,
});
try {
  const records = manifest.value.bindings.map((binding) =>
    registerReviewedRealCandidateLinuxPostExploitSpec({
      database,
      loadedProfile: loadTrustedReviewedRealCandidateLinuxProfile({
        path: binding.handlerProfilePath,
        trustRoot,
        expectedSha256: binding.handlerProfileSha256,
        allowedOwnerUids: [0],
        maximumBytes: 64 * 1_024,
      }),
      binding,
      createdBy: "system:reviewed-real-candidate-registration",
    }));
  process.stdout.write(`${JSON.stringify({
    status: "registered",
    manifestSha256: manifest.receipt.sourceSha256,
    records: records.map((record) => ({
      id: record.id,
      specHash: record.specHash,
      transportBindingId: record.transportBindingId,
    })),
  })}\n`);
} finally {
  database.close();
}

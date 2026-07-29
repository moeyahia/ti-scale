import { createHash } from "node:crypto";
import {
  readFileSync,
} from "node:fs";
import {
  CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
  CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
  parseCandidateLinuxTransportBindingManifest,
  DISPOSABLE_LOCAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
  parseDisposableLocalCandidateLinuxProfile,
  type CandidateLinuxTransportBindingManifest,
  type DisposableLocalCandidateLinuxProfile,
} from "../../server/autonomous-runtime";
import {
  exactCandidateLinuxTargetScope,
} from "../../server/autonomous-runtime/CandidateLinuxTargetScope";

const OPERATIONS = Object.freeze([
  "open",
  "observe_identity",
  "prove_user_flag_hash",
  "close",
  "privilege_escalation",
  "observe_root_identity",
  "prove_root_flag_hash",
  "cleanup",
] as const);

function canonicalBytes(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256Bytes(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export interface DisposableCandidateLinuxTransportBundleInput {
  readonly bundleVersion: string;
  readonly profileId: string;
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly postExploitSpecSha256: string;
  readonly exactTarget: "127.0.0.1" | "127.0.0.2" | "::1";
  readonly expectedPrincipal: string;
  readonly expectedUid: number;
  readonly expectedGid: number;
  readonly expectedGroups: readonly string[];
  readonly declaredUserFlagPath: string;
  readonly brokerExecutablePath: string;
  readonly brokerSocketPath: string;
  readonly brokerSocketGid: number;
  readonly handlerProfilePath: string;
  readonly userProofFilePath: string;
  readonly rootProofFilePath: string;
  readonly stateFilePath: string;
  readonly userProofBytes: Buffer;
  readonly rootProofBytes: Buffer;
}

export interface DisposableCandidateLinuxTransportBundle {
  readonly profile:
    DisposableLocalCandidateLinuxProfile;
  readonly profileBytes: string;
  readonly profileSha256: string;
  readonly manifest: CandidateLinuxTransportBindingManifest;
  readonly manifestBytes: string;
  readonly manifestSha256: string;
  readonly brokerExecutableSha256: string;
  readonly userProofSha256: string;
  readonly rootProofSha256: string;
}

export function createDisposableCandidateLinuxTransportBundle(
  input: DisposableCandidateLinuxTransportBundleInput,
): DisposableCandidateLinuxTransportBundle {
  if (input.userProofBytes.byteLength < 1
    || input.userProofBytes.byteLength > 4_096
    || input.rootProofBytes.byteLength < 1
    || input.rootProofBytes.byteLength > 4_096) {
    throw new RangeError("Disposable proof fixtures must be 1 through 4096 bytes");
  }
  const brokerExecutableSha256 = sha256Bytes(
    readFileSync(input.brokerExecutablePath),
  );
  const userProofSha256 = sha256Bytes(input.userProofBytes);
  const rootProofSha256 = sha256Bytes(input.rootProofBytes);
  const profile = parseDisposableLocalCandidateLinuxProfile({
    schemaVersion: DISPOSABLE_LOCAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
    profileId: input.profileId,
    candidateClass: "disposable_local_fixture_v1",
    disposableSimulationOnly: true,
    realTargetSupport: false,
    bindingId: input.bindingId,
    postExploitSpecId: input.postExploitSpecId,
    postExploitSpecSha256: input.postExploitSpecSha256,
    exactTarget: input.exactTarget,
    identity: {
      principal: input.expectedPrincipal,
      uid: input.expectedUid,
      gid: input.expectedGid,
      groups: input.expectedGroups,
    },
    userProof: {
      declaredPath: input.declaredUserFlagPath,
      sourceFilePath: input.userProofFilePath,
      expectedSha256: userProofSha256,
    },
    rootProof: {
      declaredPath: "/root/root.txt",
      sourceFilePath: input.rootProofFilePath,
      expectedSha256: rootProofSha256,
    },
    stateFilePath: input.stateFilePath,
  });
  const profileBytes = canonicalBytes(profile);
  const profileSha256 = sha256Bytes(profileBytes);
  const manifest = parseCandidateLinuxTransportBindingManifest({
    schemaVersion:
      CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
    bundleVersion: input.bundleVersion,
    broker: {
      executablePath: input.brokerExecutablePath,
      executableSha256: brokerExecutableSha256,
      socketPath: input.brokerSocketPath,
      socketGid: input.brokerSocketGid,
      protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
    },
    boundary: {
      typedOperationsOnly: true,
      genericCommand: false,
      shell: false,
      argv: false,
      payload: false,
      credentials: false,
      exactTargetFromCanonicalAction: true,
      succeededAttackAttemptRequired: true,
      publicProvider: false,
    },
    bindings: [{
      bindingId: input.bindingId,
      postExploitSpecId: input.postExploitSpecId,
      postExploitSpecSha256: input.postExploitSpecSha256,
      candidateClass: "disposable_local_fixture_v1",
      handlerProfilePath: input.handlerProfilePath,
      handlerProfileSha256: profileSha256,
      realTargetSupport: false,
      targetScope: exactCandidateLinuxTargetScope(input.exactTarget),
      operations: OPERATIONS,
    }],
  });
  const manifestBytes = canonicalBytes(manifest);
  return Object.freeze({
    profile,
    profileBytes,
    profileSha256,
    manifest,
    manifestBytes,
    manifestSha256: sha256Bytes(manifestBytes),
    brokerExecutableSha256,
    userProofSha256,
    rootProofSha256,
  });
}

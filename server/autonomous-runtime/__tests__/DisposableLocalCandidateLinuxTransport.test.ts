import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  createDisposableCandidateLinuxTransportBundle,
} from "../../../scripts/release/DisposableCandidateLinuxTransportBundle";
import {
  loadTrustedDisposableLocalCandidateLinuxProfile,
} from "../DisposableLocalCandidateLinuxTransport";
import {
  DisposableLocalCandidateLinuxTransportHandler,
} from "../DisposableLocalCandidateLinuxTransport";

const roots: string[] = [];
const HASH = "a".repeat(64);
const now = () => new Date("2026-07-23T14:00:00.000Z");

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-disposable-candidate-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const executable = join(root, "broker.js");
  const profilePath = join(root, "profile.json");
  const userProofPath = join(root, "user.txt");
  const rootProofPath = join(root, "root.txt");
  const statePath = join(root, "state", "state.json");
  const userProof = Buffer.from("fixture-user-objective\n");
  const rootProof = Buffer.from("fixture-root-objective\n");
  writeFileSync(executable, "process.exit(0)\n", { mode: 0o700 });
  writeFileSync(userProofPath, userProof, { mode: 0o600 });
  writeFileSync(rootProofPath, rootProof, { mode: 0o600 });
  const bundle = createDisposableCandidateLinuxTransportBundle({
    bundleVersion: "test-1",
    profileId: "profile:test",
    bindingId: "binding:test",
    postExploitSpecId: "spec:test",
    postExploitSpecSha256: HASH,
    exactTarget: "127.0.0.2",
    expectedPrincipal: "candidate",
    expectedUid: 1001,
    expectedGid: 1001,
    expectedGroups: ["candidate"],
    declaredUserFlagPath: "/home/candidate/user.txt",
    brokerExecutablePath: executable,
    brokerSocketPath: join(root, "broker.sock"),
    brokerSocketGid: process.getgid?.() ?? 0,
    handlerProfilePath: profilePath,
    userProofFilePath: userProofPath,
    rootProofFilePath: rootProofPath,
    stateFilePath: statePath,
    userProofBytes: userProof,
    rootProofBytes: rootProof,
  });
  writeFileSync(profilePath, bundle.profileBytes, { mode: 0o600 });
  const loadedProfile = loadTrustedDisposableLocalCandidateLinuxProfile({
    path: profilePath,
    trustRoot: root,
    expectedSha256: bundle.profileSha256,
    allowedOwnerUids: [process.getuid?.() ?? 0],
  });
  const handler = () => new DisposableLocalCandidateLinuxTransportHandler({
    loadedProfile,
    binding: bundle.manifest.bindings[0]!,
    allowedProofFileOwnerUids: [process.getuid?.() ?? 0],
    now,
  });
  return {
    bundle,
    handler,
    rootProof,
    statePath,
    userProof,
  };
}

function common() {
  return {
    transportBindingId: "binding:test",
    postExploitSpecId: "spec:test",
    sessionArtifactId: "session:test",
    exactTarget: "127.0.0.2",
  } as const;
}

describe("DisposableLocalCandidateLinuxTransportHandler", () => {
  test("runs the typed hash-only identity-to-cleanup sequence and survives restart", async () => {
    const fixtureState = fixture();
    const signal = new AbortController().signal;
    let handler = fixtureState.handler();
    expect(fixtureState.bundle.manifest.bindings[0]).toMatchObject({
      candidateClass: "disposable_local_fixture_v1",
      realTargetSupport: false,
    });
    expect(await handler.handle({
      operation: "open",
      ...common(),
    }, signal)).toEqual({
      accepted: true,
      sessionArtifactId: "session:test",
    });
    expect(await handler.handle({
      operation: "observe_identity",
      ...common(),
    }, signal)).toEqual({
      sessionArtifactId: "session:test",
      principal: "candidate",
      uid: 1001,
      gid: 1001,
      groups: ["candidate"],
    });
    const userProof = await handler.handle({
      operation: "prove_user_flag_hash",
      ...common(),
      declaredPath: "/home/candidate/user.txt",
    }, signal);
    expect(userProof).toMatchObject({
      sessionArtifactId: "session:test",
      declaredPath: "/home/candidate/user.txt",
      sha256: createHash("sha256").update(fixtureState.userProof).digest("hex"),
      byteSize: fixtureState.userProof.byteLength,
    });
    handler = fixtureState.handler();
    const privileged = {
      ...common(),
      candidateBindingHash: "b".repeat(64),
      leaseFencingToken: 3,
      actionId: "action:privilege",
    } as const;
    const escalation = await handler.handle({
      operation: "privilege_escalation",
      ...privileged,
    }, signal);
    const identity = await handler.handle({
      operation: "observe_root_identity",
      ...privileged,
    }, signal);
    const rootProof = await handler.handle({
      operation: "prove_root_flag_hash",
      ...privileged,
      declaredPath: "/root/root.txt",
    }, signal);
    const cleanup = await handler.handle({
      operation: "cleanup",
      ...common(),
      candidateBindingHash: "b".repeat(64),
      leaseFencingToken: 3,
      reason: "fixture complete",
    }, signal);
    expect(escalation).toMatchObject({ accepted: true });
    expect(identity).toMatchObject({ principal: "root", uid: 0, gid: 0 });
    expect(rootProof).toMatchObject({
      declaredPath: "/root/root.txt",
      contentSha256: createHash("sha256")
        .update(fixtureState.rootProof)
        .digest("hex"),
      byteSize: fixtureState.rootProof.byteLength,
    });
    expect(cleanup).toMatchObject({ closed: true });
    const serialized = JSON.stringify({
      escalation,
      identity,
      rootProof,
      cleanup,
    });
    expect(serialized).not.toContain("fixture-user-objective");
    expect(serialized).not.toContain("fixture-root-objective");
    expect(readFileSync(fixtureState.statePath, "utf8")).toContain(
      "\"stage\":\"closed\"",
    );
  });

  test("rejects target drift, root proof before privilege, stale fence, and proof-file drift", async () => {
    const fixtureState = fixture();
    const handler = fixtureState.handler();
    const signal = new AbortController().signal;
    await expect(handler.handle({
      operation: "open",
      ...common(),
      exactTarget: "127.0.0.1",
    }, signal)).rejects.toThrow("candidate identity");
    await handler.handle({ operation: "open", ...common() }, signal);
    await expect(handler.handle({
      operation: "prove_root_flag_hash",
      ...common(),
      candidateBindingHash: "b".repeat(64),
      leaseFencingToken: 1,
      actionId: "action:root",
      declaredPath: "/root/root.txt",
    }, signal)).rejects.toThrow("required state");
    await handler.handle({
      operation: "privilege_escalation",
      ...common(),
      candidateBindingHash: "b".repeat(64),
      leaseFencingToken: 1,
      actionId: "action:privilege",
    }, signal);
    await expect(handler.handle({
      operation: "observe_root_identity",
      ...common(),
      candidateBindingHash: "b".repeat(64),
      leaseFencingToken: 2,
      actionId: "action:privilege",
    }, signal)).rejects.toThrow("session fence");
    writeFileSync(
      fixtureState.bundle.profile.userProof.sourceFilePath,
      "changed\n",
      { mode: 0o600 },
    );
    await expect(handler.handle({
      operation: "prove_user_flag_hash",
      ...common(),
      declaredPath: "/home/candidate/user.txt",
    }, signal)).rejects.toThrow("required state");
  });

  test("a reviewed real-candidate manifest remains representable but cannot reuse the fixture profile", () => {
    const fixtureState = fixture();
    const realBinding = {
      ...fixtureState.bundle.manifest.bindings[0]!,
      candidateClass: "reviewed_real_candidate_v1" as const,
      realTargetSupport: true as const,
    };
    expect(() => new DisposableLocalCandidateLinuxTransportHandler({
      loadedProfile: loadTrustedDisposableLocalCandidateLinuxProfile({
        path: fixtureState.bundle.manifest.bindings[0]!.handlerProfilePath,
        trustRoot: fixtureState.bundle.manifest.bindings[0]!.handlerProfilePath
          .replace(/\/profile\.json$/u, ""),
        expectedSha256:
          fixtureState.bundle.manifest.bindings[0]!.handlerProfileSha256,
        allowedOwnerUids: [process.getuid?.() ?? 0],
      }),
      binding: realBinding,
      allowedProofFileOwnerUids: [process.getuid?.() ?? 0],
    })).toThrow("does not match");
  });
});

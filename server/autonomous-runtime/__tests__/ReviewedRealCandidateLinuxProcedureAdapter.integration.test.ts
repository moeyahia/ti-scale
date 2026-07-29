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
  HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider,
  ProcedureBackedReviewedRealCandidateLinuxAdapterImplementation,
} from "../ReviewedRealCandidateLinuxProcedureAdapter";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
  loadTrustedReviewedRealCandidateLinuxProfile,
  reviewedRealCandidateLinuxOperations,
} from "../ReviewedRealCandidateLinuxTransport";
import {
  exactCandidateLinuxTargetScope,
} from "../CandidateLinuxTargetScope";

const NOW = new Date("2026-07-28T12:00:00.000Z");
const BINDING_ID = "binding.reviewed-real-procedure-integration";
const SOURCE_SPEC_ID = "spec.reviewed-real-procedure-source";
const DERIVED_SPEC_ID = "spec.reviewed-real-procedure-current-run";
const SCRIPT_ID = "script.reviewed-real-procedure";
const OBSERVER_ID = "observer.reviewed-real-procedure";
const USER_HASH = createHash("sha256")
  .update("fixture-user-proof", "utf8")
  .digest("hex");
const ROOT_HASH = createHash("sha256")
  .update("fixture-root-proof", "utf8")
  .digest("hex");
const TARGET_SCOPE = exactCandidateLinuxTargetScope("10.129.10.20");
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function procedureSource(statePath: string): string {
  return `#!/usr/bin/env bun
import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

const OPERATIONS = ${JSON.stringify(reviewedRealCandidateLinuxOperations())};
const BOUNDARY = ${JSON.stringify({
  typedOperationsOnly: true,
  genericCommand: false,
  shell: false,
  argv: false,
  payload: false,
  credentialsFromRuntime: false,
  exactTargetFromCanonicalAction: true,
  succeededAttackAttemptRequired: true,
  derivedCurrentRunSpecOnly: true,
  publicProvider: false,
  hashOnlyFlagProofs: true,
})};
const STATE_PATH = ${JSON.stringify(statePath)};
const NOW = ${JSON.stringify(NOW.toISOString())};
const USER_HASH = ${JSON.stringify(USER_HASH)};
const ROOT_HASH = ${JSON.stringify(ROOT_HASH)};
const encode = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(encode).join(",") + "]";
  return "{" + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ":" + encode(value[key])).join(",") + "}";
};
const digest = (value) =>
  createHash("sha256").update(encode(value), "utf8").digest("hex");
const success = (result) => process.stdout.write(JSON.stringify({ ok: true, result }) + "\\n");
const fail = (message) => {
  process.stdout.write(JSON.stringify({
    ok: false,
    error: { code: "fixture_rejected", message },
  }) + "\\n");
  process.exitCode = 1;
};
const input = JSON.parse((await Bun.stdin.text()).trim());
if (input.operation === "attest") {
  const unsigned = {
    schemaVersion: "ti-scale.reviewed-real-candidate-linux-procedure-attestation.v1",
    protocolVersion: "ti-scale.reviewed-real-candidate-linux-procedure.v1",
    profileSha256: input.profileSha256,
    procedureExecutableSha256: input.procedureExecutableSha256,
    bindingId: input.bindingId,
    postExploitSpecId: input.postExploitSpecId,
    scriptArtifactId: input.scriptArtifactId,
    exploitOutcomeObserverSpecId: input.exploitOutcomeObserverSpecId,
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: input.targetScope,
    operations: OPERATIONS,
    boundary: BOUNDARY,
    observedAt: NOW,
    expiresAt: new Date(Date.parse(NOW) + 60_000).toISOString(),
  };
  success({ ...unsigned, receiptSha256: digest(unsigned) });
} else if (input.operation === "conformance") {
  const cases = [
    { operation: "open", result: { accepted: true } },
    {
      operation: "observe_identity",
      result: {
        principal: "operator",
        uid: 1000,
        gid: 1000,
        groups: ["operator"],
      },
    },
    {
      operation: "prove_user_flag_hash",
      result: { sha256: USER_HASH, byteSize: 18 },
    },
    { operation: "close", result: { closed: true } },
    { operation: "privilege_escalation", result: { accepted: true } },
    {
      operation: "observe_root_identity",
      result: { principal: "root", uid: 0, gid: 0, groups: ["root"] },
    },
    {
      operation: "prove_root_flag_hash",
      result: { sha256: ROOT_HASH, byteSize: 18 },
    },
    { operation: "cleanup", result: { closed: true } },
  ];
  const unsigned = {
    schemaVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure-conformance.v1",
    protocolVersion: "ti-scale.reviewed-real-candidate-linux-procedure.v1",
    profileSha256: input.profileSha256,
    procedureExecutableSha256: input.procedureExecutableSha256,
    bindingId: input.bindingId,
    postExploitSpecId: input.postExploitSpecId,
    scriptArtifactId: input.scriptArtifactId,
    exploitOutcomeObserverSpecId: input.exploitOutcomeObserverSpecId,
    targetScope: input.targetScope,
    cases,
  };
  success({ ...unsigned, receiptSha256: digest(unsigned) });
} else if (input.operation === "invoke") {
  const request = input.request;
  if (!request || Object.keys(request).some((field) =>
    ["command", "argv", "shell", "payload", "credentials", "secret"].includes(field))) {
    fail("request widened");
  } else {
    const state = existsSync(STATE_PATH)
      ? JSON.parse(readFileSync(STATE_PATH, "utf8"))
      : { sessions: {} };
    const persist = () => {
      const temporary = STATE_PATH + ".tmp";
      writeFileSync(temporary, JSON.stringify(state) + "\\n", { mode: 0o600 });
      renameSync(temporary, STATE_PATH);
    };
    const session = state.sessions[request.sessionArtifactId];
    if (request.sessionArtifactId === "session-procedure-cancel") {
      await Bun.sleep(5_000);
    }
    if (request.exactTarget !== "10.129.10.20"
      || request.transportBindingId !== ${JSON.stringify(BINDING_ID)}
      || request.postExploitSpecId !== ${JSON.stringify(DERIVED_SPEC_ID)}) {
      fail("identity mismatch");
    } else if (request.operation === "open") {
      state.sessions[request.sessionArtifactId] = {
        exactTarget: request.exactTarget,
        stage: "open",
      };
      persist();
      success(request.sessionArtifactId === "session-procedure-widened"
        ? { accepted: true, command: "forbidden" }
        : { accepted: true });
    } else if (!session || session.exactTarget !== request.exactTarget) {
      fail("session missing");
    } else if (request.operation === "observe_identity" && session.stage === "open") {
      success({ principal: "operator", uid: 1000, gid: 1000, groups: ["operator"] });
    } else if (request.operation === "prove_user_flag_hash" && session.stage === "open") {
      success({ sha256: USER_HASH, byteSize: 18 });
    } else if (request.operation === "close") {
      session.stage = "closed";
      persist();
      success({ closed: true });
    } else if (request.operation === "privilege_escalation"
      && ["open", "privileged"].includes(session.stage)) {
      if (session.stage === "privileged"
        && (session.fence !== request.leaseFencingToken
          || session.hash !== request.candidateBindingHash
          || session.actionId !== request.actionId)) {
        fail("privilege fence mismatch");
      } else {
        session.stage = "privileged";
        session.fence = request.leaseFencingToken;
        session.hash = request.candidateBindingHash;
        session.actionId = request.actionId;
        persist();
        success({ accepted: true });
      }
    } else if (request.operation === "observe_root_identity"
      && session.stage === "privileged"
      && session.fence === request.leaseFencingToken
      && session.hash === request.candidateBindingHash
      && session.actionId === request.actionId) {
      success({ principal: "root", uid: 0, gid: 0, groups: ["root"] });
    } else if (request.operation === "prove_root_flag_hash"
      && session.stage === "privileged"
      && session.fence === request.leaseFencingToken
      && session.hash === request.candidateBindingHash
      && request.declaredPath === "/root/root.txt") {
      success({ sha256: ROOT_HASH, byteSize: 18 });
    } else if (request.operation === "cleanup"
      && session.stage === "privileged"
      && session.fence === request.leaseFencingToken
      && session.hash === request.candidateBindingHash) {
      session.stage = "closed";
      persist();
      success({ closed: true });
    } else {
      fail("operation or state rejected");
    }
  }
} else {
  fail("unsupported envelope");
}
`;
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-procedure-adapter-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const adapterPath = join(root, "adapter");
  const procedurePath = join(root, "procedure");
  const statePath = join(root, "procedure-state.json");
  writeFileSync(
    adapterPath,
    "#!/usr/bin/env bun\n// pinned adapter executable identity\n",
    { mode: 0o500 },
  );
  writeFileSync(procedurePath, procedureSource(statePath), { mode: 0o500 });
  const adapterHash = sha256(adapterPath);
  const procedureHash = sha256(procedurePath);
  const profile = {
    schemaVersion: REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
    profileId: "profile.reviewed-real-procedure-integration",
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: TARGET_SCOPE,
    bindingId: BINDING_ID,
    postExploitSpec: {
      id: SOURCE_SPEC_ID,
      expectedSha256: "d".repeat(64),
      exploitOutcomeObserverSpecId: OBSERVER_ID,
      scriptArtifactId: SCRIPT_ID,
      expectedPrincipal: "operator",
      expectedUid: 1_000,
      declaredUserFlagPath: "/home/operator/user.txt",
      declaredRootFlagPath: "/root/root.txt",
    },
    adapter: {
      executablePath: adapterPath,
      executableSha256: adapterHash,
      socketPath: join(root, "adapter.sock"),
      socketGid: process.getgid?.() ?? 0,
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
    },
    procedure: {
      executablePath: procedurePath,
      executableSha256: procedureHash,
      protocolVersion:
        "ti-scale.reviewed-real-candidate-linux-procedure.v1",
    },
    boundary: {
      typedOperationsOnly: true,
      genericCommand: false,
      shell: false,
      argv: false,
      payload: false,
      credentialsFromRuntime: false,
      exactTargetFromCanonicalAction: true,
      succeededAttackAttemptRequired: true,
      derivedCurrentRunSpecOnly: true,
      publicProvider: false,
      hashOnlyFlagProofs: true,
    },
    operations: reviewedRealCandidateLinuxOperations(),
  };
  const profilePath = join(root, "profile.json");
  const profileBytes = `${JSON.stringify(profile)}\n`;
  writeFileSync(profilePath, profileBytes, { mode: 0o600 });
  const profileHash = createHash("sha256")
    .update(profileBytes, "utf8")
    .digest("hex");
  const loadedProfile = loadTrustedReviewedRealCandidateLinuxProfile({
    path: profilePath,
    trustRoot: root,
    expectedSha256: profileHash,
    allowedOwnerUids: [process.getuid?.() ?? 0],
  });
  const provider =
    new HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider({
      profile: loadedProfile.value,
      profileSha256: loadedProfile.receipt.sourceSha256,
      procedureExecutablePath: procedurePath,
      procedureExecutableSha256: procedureHash,
      allowedOwnerUids: [process.getuid?.() ?? 0],
      now: () => NOW,
    });
  const implementation =
    new ProcedureBackedReviewedRealCandidateLinuxAdapterImplementation({
      profile: loadedProfile.value,
      profileSha256: loadedProfile.receipt.sourceSha256,
      adapterExecutableSha256: adapterHash,
      provider,
      now: () => NOW,
    });
  return Object.freeze({
    root,
    procedurePath,
    procedureHash,
    provider,
    implementation,
  });
}

function common(sessionArtifactId: string) {
  return {
    transportBindingId: BINDING_ID,
    postExploitSpecId: DERIVED_SPEC_ID,
    sessionArtifactId,
    exactTarget: "10.129.10.20",
  } as const;
}

describe("procedure-backed reviewed real-candidate Linux adapter", () => {
  test.each([
    "127.0.0.2",
    "10.129.39.191",
  ])("rejects dispatch outside the provider's exact reviewed target scope (%s)", async (exactTarget) => {
    const { provider } = fixture();
    await expect(provider.invoke({
      ...common("session-outside-target-scope"),
      exactTarget,
      operation: "open",
    }, new AbortController().signal)).rejects.toThrow(
      "unavailable for this exact target",
    );
  });

  test("executes the eight closed operations through a hash-pinned process and returns hash-only proofs", async () => {
    const { implementation, provider } = fixture();
    const signal = new AbortController().signal;
    const attestation = await provider.attest(signal);
    expect(attestation).toMatchObject({
      profileSha256: implementation.profileSha256,
      procedureExecutableSha256: provider.procedureExecutableSha256,
      bindingId: BINDING_ID,
      postExploitSpecId: SOURCE_SPEC_ID,
      scriptArtifactId: SCRIPT_ID,
      exploitOutcomeObserverSpecId: OBSERVER_ID,
      realTargetSupport: true,
    });
    const conformance = await provider.conform(signal);
    expect(conformance.cases.map(({ operation }) => operation)).toEqual(
      [...reviewedRealCandidateLinuxOperations()],
    );
    await implementation.attest(signal);

    const closedSession = common("session-procedure-close");
    expect(await implementation.handle({
      ...closedSession,
      operation: "open",
    }, signal)).toEqual({
      accepted: true,
      sessionArtifactId: closedSession.sessionArtifactId,
    });
    expect(await implementation.handle({
      ...closedSession,
      operation: "close",
    }, signal)).toEqual({
      closed: true,
      sessionArtifactId: closedSession.sessionArtifactId,
    });

    const privileged = common("session-procedure-privileged");
    await implementation.handle({ ...privileged, operation: "open" }, signal);
    expect(await implementation.handle({
      ...privileged,
      operation: "observe_identity",
    }, signal)).toMatchObject({
      principal: "operator",
      uid: 1_000,
      gid: 1_000,
    });
    const userProof = await implementation.handle({
      ...privileged,
      operation: "prove_user_flag_hash",
      declaredPath: "/home/operator/user.txt",
    }, signal);
    expect(userProof).toMatchObject({
      sha256: USER_HASH,
      byteSize: 18,
      declaredPath: "/home/operator/user.txt",
    });
    const fence = {
      candidateBindingHash: "a".repeat(64),
      leaseFencingToken: 7,
    } as const;
    expect(await implementation.handle({
      ...privileged,
      ...fence,
      operation: "privilege_escalation",
      actionId: "action-procedure-privilege",
    }, signal)).toMatchObject({
      accepted: true,
      sessionArtifactId: privileged.sessionArtifactId,
    });
    expect(await implementation.handle({
      ...privileged,
      ...fence,
      operation: "observe_root_identity",
      actionId: "action-procedure-privilege",
    }, signal)).toMatchObject({
      principal: "root",
      uid: 0,
      gid: 0,
    });
    const rootProof = await implementation.handle({
      ...privileged,
      ...fence,
      operation: "prove_root_flag_hash",
      actionId: "action-procedure-root-proof",
      declaredPath: "/root/root.txt",
    }, signal);
    expect(rootProof).toMatchObject({
      contentSha256: ROOT_HASH,
      byteSize: 18,
      declaredPath: "/root/root.txt",
    });
    expect(await implementation.handle({
      ...privileged,
      ...fence,
      operation: "cleanup",
      reason: "Close the represented candidate session.",
    }, signal)).toMatchObject({
      closed: true,
      sessionArtifactId: privileged.sessionArtifactId,
    });
    expect(JSON.stringify([userProof, rootProof])).not.toContain(
      "fixture-user-proof",
    );
    expect(JSON.stringify([userProof, rootProof])).not.toContain(
      "fixture-root-proof",
    );
  });

  test("fails closed when the procedure executable changes after construction", async () => {
    const fixtureValue = fixture();
    await fixtureValue.implementation.attest(
      new AbortController().signal,
    );
    writeFileSync(
      fixtureValue.procedurePath,
      `${readFileSync(fixtureValue.procedurePath, "utf8")}\n// drift\n`,
      { mode: 0o500 },
    );
    await expect(fixtureValue.implementation.handle({
      ...common("session-procedure-drift"),
      operation: "open",
    }, new AbortController().signal)).rejects.toThrow(
      "not owner-controlled and hash-pinned",
    );
  });

  test("cancels the exact procedure process instead of leaving it running", async () => {
    const { implementation } = fixture();
    const controller = new AbortController();
    const started = performance.now();
    const pending = implementation.handle({
      ...common("session-procedure-cancel"),
      operation: "open",
    }, controller.signal);
    await Bun.sleep(40);
    controller.abort();
    await expect(pending).rejects.toThrow(
      "Reviewed candidate procedure request cancelled",
    );
    expect(performance.now() - started).toBeLessThan(1_500);
  });

  test("rejects a procedure result that attempts to widen the typed response", async () => {
    const { implementation } = fixture();
    await expect(implementation.handle({
      ...common("session-procedure-widened"),
      operation: "open",
    }, new AbortController().signal)).rejects.toThrow(
      "contains an unreviewed field",
    );
  });
});

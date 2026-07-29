import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "bun:test";
import {
  COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
  COMPLETE_AUTONOMOUS_CANDIDATE_GENERAL_EXTERNAL_TARGET_SUPPORT,
  COMPLETE_AUTONOMOUS_CANDIDATE_PROCEDURE_PROTOCOL_VERSION,
  COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET,
  COMPLETE_AUTONOMOUS_SOURCE_POST_EXPLOIT_SPEC_ID,
  renderCompleteAutonomousCandidateProcedureProvider,
} from "../testing/CompleteAutonomousCandidateProcedureProviderSource";
import {
  DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
  startDisposableCompleteAutonomousTarget,
} from "../testing/DisposableCompleteAutonomousTarget";
import {
  exactCandidateLinuxTargetScope,
} from "../CandidateLinuxTargetScope";

const PROFILE_HASH = "a".repeat(64);
const SCRIPT_ID = "script-artifact:complete-autonomous-fixture-test";
const OBSERVER_ID = "observer:complete-autonomous-fixture-test";
const PROVIDER_HASH = "b".repeat(64);
const DERIVED_SPEC_ID = "post-exploit-spec:derived-current-run-test";
const SESSION_ID = "session:complete-autonomous-fixture-test";
const BINDING_HASH = "c".repeat(64);
const TARGET_SCOPE = exactCandidateLinuxTargetScope(
  "127.0.0.2",
  { transport: "tcp", port: DISPOSABLE_COMPLETE_AUTONOMOUS_PORT },
);
const tempRoots: string[] = [];

function outer(operation: string, request?: unknown): Record<string, unknown> {
  return {
    operation,
    protocolVersion:
      COMPLETE_AUTONOMOUS_CANDIDATE_PROCEDURE_PROTOCOL_VERSION,
    profileSha256: PROFILE_HASH,
    procedureExecutableSha256: PROVIDER_HASH,
    bindingId: COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
    postExploitSpecId: COMPLETE_AUTONOMOUS_SOURCE_POST_EXPLOIT_SPEC_ID,
    scriptArtifactId: SCRIPT_ID,
    exploitOutcomeObserverSpecId: OBSERVER_ID,
    targetScope: TARGET_SCOPE,
    ...(request === undefined ? {} : { request }),
  };
}

function executable(): string {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-reviewed-provider-"));
  tempRoots.push(root);
  const path = join(root, "provider");
  writeFileSync(path, renderCompleteAutonomousCandidateProcedureProvider({
    scriptArtifactId: SCRIPT_ID,
    exploitOutcomeObserverSpecId: OBSERVER_ID,
  }), { encoding: "utf8", mode: 0o700 });
  chmodSync(path, 0o700);
  return path;
}

async function invoke(
  path: string,
  envelope: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return await new Promise((resolve, reject) => {
    const child = spawn(path, [], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code !== 0 || stderr) {
        reject(new Error(`provider failed (${String(code)}): ${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout.trim()) as Record<string, unknown>);
      } catch (error) {
        reject(error);
      }
    });
    child.stdin.end(`${JSON.stringify(envelope)}\n`);
  });
}

function request(
  operation: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    exactTarget: "127.0.0.2",
    operation,
    postExploitSpecId: DERIVED_SPEC_ID,
    sessionArtifactId: SESSION_ID,
    transportBindingId: COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
    ...extra,
  };
}

afterEach(() => {
  for (const root of tempRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("complete Autonomous reviewed candidate procedure provider", () => {
  it("attests and conforms without contacting a target", async () => {
    const path = executable();
    const sourceHash = createHash("sha256")
      .update(renderCompleteAutonomousCandidateProcedureProvider({
        scriptArtifactId: SCRIPT_ID,
        exploitOutcomeObserverSpecId: OBSERVER_ID,
      }))
      .digest("hex");
    expect(sourceHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET)
      .toBe("127.0.0.2:8080");
    expect(COMPLETE_AUTONOMOUS_CANDIDATE_GENERAL_EXTERNAL_TARGET_SUPPORT)
      .toBe(false);

    const attestation = await invoke(path, outer("attest"));
    const conformance = await invoke(path, outer("conformance"));
    expect(attestation.ok).toBe(true);
    expect((attestation.result as { operations: string[] }).operations)
      .toEqual([
        "open",
        "observe_identity",
        "prove_user_flag_hash",
        "close",
        "privilege_escalation",
        "observe_root_identity",
        "prove_root_flag_hash",
        "cleanup",
      ]);
    expect(conformance.ok).toBe(true);
    expect((conformance.result as { cases: unknown[] }).cases).toHaveLength(8);
  });

  it("maps the closed session flow only to the fixed loopback fixture", async () => {
    const target = await startDisposableCompleteAutonomousTarget(
      DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
    );
    const path = executable();
    try {
      const open = await invoke(path, outer("invoke", request("open")));
      const identity = await invoke(
        path,
        outer("invoke", request("observe_identity")),
      );
      const userProof = await invoke(
        path,
        outer("invoke", request("prove_user_flag_hash", {
          declaredPath: "/home/fixtureuser/user.txt",
        })),
      );
      const privilegeFields = {
        actionId: "action:complete-autonomous-fixture-test",
        candidateBindingHash: BINDING_HASH,
        leaseFencingToken: 1,
      };
      const privilege = await invoke(
        path,
        outer("invoke", request("privilege_escalation", privilegeFields)),
      );
      const rootIdentity = await invoke(
        path,
        outer("invoke", request("observe_root_identity", privilegeFields)),
      );
      const rootProof = await invoke(
        path,
        outer("invoke", request("prove_root_flag_hash", {
          ...privilegeFields,
          declaredPath: "/root/root.txt",
        })),
      );
      const cleanup = await invoke(
        path,
        outer("invoke", request("cleanup", {
          candidateBindingHash: BINDING_HASH,
          leaseFencingToken: 1,
          reason: "integration_test_complete",
        })),
      );

      expect(open).toMatchObject({ ok: true, result: { accepted: true } });
      expect(identity).toMatchObject({
        ok: true,
        result: { principal: "fixtureuser", uid: 1_000 },
      });
      expect(userProof).toMatchObject({
        ok: true,
        result: { byteSize: 32 },
      });
      expect(privilege).toMatchObject({
        ok: true,
        result: { accepted: true },
      });
      expect(rootIdentity).toMatchObject({
        ok: true,
        result: { principal: "root", uid: 0 },
      });
      expect(rootProof).toMatchObject({
        ok: true,
        result: { byteSize: 32 },
      });
      expect(cleanup).toMatchObject({
        ok: true,
        result: { closed: true },
      });
      expect(target.openSessionCount()).toBe(0);
      expect(target.traces().map(({ result }) => result)).toEqual([
        "session_opened",
        "user_identity_observed",
        "user_hash_proved",
        "privilege_continued",
        "root_identity_observed",
        "root_hash_proved",
        "session_closed",
      ]);
    } finally {
      await target.close();
    }
  });

  it("rejects unreviewed fields before target I/O", async () => {
    const path = executable();
    const response = await invoke(
      path,
      outer("invoke", {
        ...request("open"),
        command: "id",
      }),
    );
    expect(response).toMatchObject({
      ok: false,
      error: { code: "reviewed_fixture_provider_rejected" },
    });
  });

  it.each([
    "127.0.0.3",
    "10.129.0.1",
  ])("rejects non-fixture target %s before target I/O", async (exactTarget) => {
    const path = executable();
    const response = await invoke(
      path,
      outer("invoke", {
        ...request("open"),
        exactTarget,
      }),
    );
    expect(response).toMatchObject({
      ok: false,
      error: {
        code: "reviewed_fixture_provider_rejected",
        message: expect.stringContaining(
          "outside the exact reviewed fixture binding",
        ),
      },
    });
  });
});

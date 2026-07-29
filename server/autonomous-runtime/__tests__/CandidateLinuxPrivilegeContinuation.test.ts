import { createHash } from "node:crypto";
import { afterEach, describe, expect, test } from "bun:test";
import { digestCanonicalJson } from "../../mcp";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
  BoundedCandidateRuntimeLinuxPrivilegeAdapter,
  LoopbackCandidateLinuxPrivilegeAdapter,
  type CandidateLinuxPrivilegeSessionBinding,
} from "../CandidateLinuxPrivilegeContinuation";
import {
  buildCandidateLinuxPrivilegeContinuationSteps,
} from "../CandidateLinuxPrivilegePlanExtension";

const RAW_ROOT_FLAG = "0f4f3f925f7e4a769fde9c3dfa19ce81";
const ROOT_FLAG_SHA256 = createHash("sha256")
  .update(RAW_ROOT_FLAG, "utf8").digest("hex");
const NOW = "2026-07-23T21:00:00.000Z";
const servers: Bun.Server<undefined>[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) await server.stop(true);
});

function receipt<T extends Readonly<Record<string, unknown>>>(
  body: T,
  field: string,
): T & Readonly<Record<string, string>> {
  return Object.freeze({
    ...body,
    [field]: digestCanonicalJson(
      body,
      { maxBytes: 32 * 1_024, maxDepth: 12 },
    ).sha256,
  });
}

function startBroker(options?: Readonly<{
  leakRootFlag?: boolean;
  delayRootIdentityMs?: number;
}>): Readonly<{
  origin: string;
  counters: {
    privilege: number;
    rootIdentity: number;
    rootFlag: number;
    cleanup: number;
  };
}> {
  const counters = {
    privilege: 0,
    rootIdentity: 0,
    rootFlag: 0,
    cleanup: 0,
  };
  const privileged = new Set<string>();
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      if (request.method === "POST"
        && url.pathname === "/ti-scale/session/privilege-escalation") {
        counters.privilege += 1;
        const body = await request.json() as {
          readonly sessionArtifactId: string;
          readonly operation: string;
        };
        if (body.operation !== "privilege_escalation") {
          return new Response("invalid", { status: 400 });
        }
        privileged.add(body.sessionArtifactId);
        return Response.json(receipt({
          schemaVersion: LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
          sessionArtifactId: body.sessionArtifactId,
          accepted: true,
          observedAt: NOW,
        }, "receiptSha256"));
      }
      if (request.method === "GET"
        && url.pathname === "/ti-scale/session/root-identity") {
        counters.rootIdentity += 1;
        if (options?.delayRootIdentityMs) {
          await Promise.race([
            Bun.sleep(options.delayRootIdentityMs),
            new Promise<void>((resolve) => {
              if (request.signal.aborted) resolve();
              else request.signal.addEventListener(
                "abort",
                () => resolve(),
                { once: true },
              );
            }),
          ]);
        }
        const sessionArtifactId =
          url.searchParams.get("sessionArtifactId") ?? "";
        if (!privileged.has(sessionArtifactId)) {
          return new Response("not privileged", { status: 409 });
        }
        return Response.json(receipt({
          schemaVersion: LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
          sessionArtifactId,
          principal: "root",
          uid: 0,
          gid: 0,
          groups: ["root"],
          observedAt: NOW,
        }, "observationSha256"));
      }
      if (request.method === "POST"
        && url.pathname === "/ti-scale/session/root-flag-proof") {
        counters.rootFlag += 1;
        const body = await request.json() as {
          readonly sessionArtifactId: string;
          readonly declaredPath: string;
          readonly returnContent: boolean;
        };
        if (!privileged.has(body.sessionArtifactId)
          || body.declaredPath !== "/root/root.txt"
          || body.returnContent !== false) {
          return new Response("invalid", { status: 400 });
        }
        const proof = receipt({
          schemaVersion: LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
          sessionArtifactId: body.sessionArtifactId,
          declaredPath: "/root/root.txt",
          contentSha256: ROOT_FLAG_SHA256,
          byteSize: Buffer.byteLength(RAW_ROOT_FLAG, "utf8"),
          observedAt: NOW,
          ...(options?.leakRootFlag ? { flagContent: RAW_ROOT_FLAG } : {}),
        }, "proofSha256");
        return Response.json(proof);
      }
      if (request.method === "POST"
        && url.pathname === "/ti-scale/session/cleanup") {
        counters.cleanup += 1;
        const body = await request.json() as {
          readonly sessionArtifactId: string;
        };
        privileged.delete(body.sessionArtifactId);
        return Response.json(receipt({
          schemaVersion: LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
          sessionArtifactId: body.sessionArtifactId,
          closed: true,
          observedAt: NOW,
        }, "receiptSha256"));
      }
      return new Response("not found", { status: 404 });
    },
  });
  servers.push(server);
  return Object.freeze({
    origin: `http://127.0.0.1:${server.port}`,
    counters,
  });
}

function binding(origin: string): CandidateLinuxPrivilegeSessionBinding {
  return Object.freeze({
    sessionArtifactId: "session-fixture-root-proof",
    postExploitSpecId: "post-exploit-fixture-root-proof",
    missionId: "mission-fixture-root-proof",
    runId: "run-fixture-root-proof",
    exactTarget: "127.0.0.1",
    candidateBindingHash: "a".repeat(64),
    leaseFencingToken: 3,
    transportType: "loopback_http_session_v1",
    transportBindingId: "fixture-loopback-linux-root-v1",
    transportOrigin: origin,
    privilegePath: "/ti-scale/session/privilege-escalation",
    rootIdentityPath: "/ti-scale/session/root-identity",
    rootFlagProofPath: "/ti-scale/session/root-flag-proof",
    cleanupPath: "/ti-scale/session/cleanup",
    declaredRootFlagPath: "/root/root.txt",
  });
}

describe("candidate-bound Linux privilege continuation", () => {
  test("builds the exact privilege -> root proof -> cleanup continuation without runtime lease data in the plan", () => {
    const steps = buildCandidateLinuxPrivilegeContinuationSteps({
      exactTarget: "127.0.0.1",
      postExploitSpecId: "post-exploit-fixture-root-proof",
      sessionArtifactId: "session-fixture-root-proof",
      assignedAgentId: "agent-linux-post-exploit",
      dependencyOrdinal: 2,
    });
    expect(steps.map((step) => ({
      actionType: step.action.actionType,
      actionClass: step.action.actionClass,
      dependencyOrdinals: step.dependencyOrdinals,
      idempotent: step.action.idempotent,
      arguments: step.action.arguments,
    }))).toEqual([
      {
        actionType: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
        actionClass: "privilege_escalation",
        dependencyOrdinals: [2],
        idempotent: false,
        arguments: {
          schemaVersion:
            "ti-scale.autonomous-linux-privilege-action-arguments.v1",
          postExploitSpecId: "post-exploit-fixture-root-proof",
          sessionArtifactId: "session-fixture-root-proof",
        },
      },
      {
        actionType: AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
        actionClass: "data_access_impact_validation",
        dependencyOrdinals: [3],
        idempotent: true,
        arguments: {
          schemaVersion:
            "ti-scale.autonomous-linux-privilege-action-arguments.v1",
          postExploitSpecId: "post-exploit-fixture-root-proof",
          sessionArtifactId: "session-fixture-root-proof",
          declaredPath: "/root/root.txt",
        },
      },
      {
        actionType: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
        actionClass: "cleanup_restoration",
        dependencyOrdinals: [4],
        idempotent: true,
        arguments: {
          schemaVersion:
            "ti-scale.autonomous-linux-privilege-action-arguments.v1",
          postExploitSpecId: "post-exploit-fixture-root-proof",
          sessionArtifactId: "session-fixture-root-proof",
        },
      },
    ]);
    const serialized = JSON.stringify(
      steps.map(({ action }) => action.arguments),
    );
    expect(serialized).not.toContain("candidateBindingHash");
    expect(serialized).not.toContain("leaseFencingToken");
    expect(serialized).not.toContain("command");
    expect(serialized).not.toContain("shell");
  });

  test("uses separate privilege and identity requests, retains a hash-only root proof, and closes the session", async () => {
    const broker = startBroker();
    const adapter = new LoopbackCandidateLinuxPrivilegeAdapter();
    const candidate = binding(broker.origin);
    const signal = new AbortController().signal;
    const privilege = await adapter.requestPrivilegeEscalation(
      candidate,
      "action-privilege",
      signal,
    );
    expect(privilege).toMatchObject({ accepted: true });
    expect(JSON.stringify(privilege)).not.toContain("principal");
    expect(broker.counters).toMatchObject({
      privilege: 1,
      rootIdentity: 0,
    });

    const identity = await adapter.observeRootIdentity(
      candidate,
      "action-privilege",
      signal,
    );
    expect(identity).toMatchObject({
      principal: "root",
      uid: 0,
      gid: 0,
    });
    expect(broker.counters).toMatchObject({
      privilege: 1,
      rootIdentity: 1,
    });

    const proof = await adapter.proveRootFlag(
      candidate,
      "action-root-proof",
      signal,
    );
    expect(proof).toMatchObject({
      declaredPath: "/root/root.txt",
      contentSha256: ROOT_FLAG_SHA256,
      byteSize: Buffer.byteLength(RAW_ROOT_FLAG, "utf8"),
    });
    expect(JSON.stringify(proof)).not.toContain(RAW_ROOT_FLAG);

    const cleanup = await adapter.cleanup(
      candidate,
      "fixture proof complete",
      signal,
    );
    expect(cleanup.closed).toBeTrue();
    expect(broker.counters).toEqual({
      privilege: 1,
      rootIdentity: 1,
      rootFlag: 1,
      cleanup: 1,
    });
  });

  test("rejects any root-proof response that includes raw flag content", async () => {
    const broker = startBroker({ leakRootFlag: true });
    const adapter = new LoopbackCandidateLinuxPrivilegeAdapter();
    const candidate = binding(broker.origin);
    const signal = new AbortController().signal;
    await adapter.requestPrivilegeEscalation(
      candidate,
      "action-privilege",
      signal,
    );
    await adapter.observeRootIdentity(
      candidate,
      "action-privilege",
      signal,
    );
    await expect(adapter.proveRootFlag(
      candidate,
      "action-root-proof",
      signal,
    )).rejects.toMatchObject({
      code: "autonomous_linux_root_flag_proof_invalid",
    });
  });

  test("aborts a delayed independent identity observation", async () => {
    let identityRequests = 0;
    const adapter = new BoundedCandidateRuntimeLinuxPrivilegeAdapter({
      invoke: async (request, signal) => {
        if (request.operation === "privilege_escalation") {
          return receipt({
            schemaVersion: LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
            sessionArtifactId: request.sessionArtifactId,
            accepted: true,
            observedAt: NOW,
          }, "receiptSha256");
        }
        identityRequests += 1;
        return await new Promise<never>((_resolve, reject) => {
          if (signal.aborted) {
            reject(signal.reason);
            return;
          }
          signal.addEventListener(
            "abort",
            () => reject(signal.reason),
            { once: true },
          );
        });
      },
    });
    const candidate: CandidateLinuxPrivilegeSessionBinding = Object.freeze({
      ...binding("http://127.0.0.1:1"),
      transportType: "candidate_runtime_session_v1",
      transportBindingId: "reviewed-candidate-runtime-root-v1",
      transportOrigin: undefined,
    });
    await adapter.requestPrivilegeEscalation(
      candidate,
      "action-privilege",
      new AbortController().signal,
    );
    const controller = new AbortController();
    const observation = adapter.observeRootIdentity(
      candidate,
      "action-privilege",
      controller.signal,
    );
    while (identityRequests === 0) await Bun.sleep(2);
    controller.abort(new Error("operator cancelled fixture"));
    await expect(observation).rejects.toThrow();
  });
});

import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import type { SqliteDatabase } from "../../db";
import { digestCanonicalJson } from "../../mcp";
import {
  CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
  CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
  CandidateLinuxTransportBindingRegistry,
  loadTrustedCandidateLinuxTransportBindingManifest,
} from "../CandidateLinuxTransportBindingRegistry";
import {
  candidateLinuxPostExploitSpecificationHash,
} from "../CandidateLinuxPostExploitSpecRegistry";
import {
  startCandidateLinuxTransportBroker,
  type CandidateLinuxTransportBrokerHandle,
} from "../CandidateLinuxTransportBroker";
import {
  allAuthorizedIpCandidateLinuxTargetScope,
} from "../CandidateLinuxTargetScope";

const SPEC_ID = "post-exploit-spec-1";
const BINDING_ID = "candidate.linux.fixture.v1";
const SCRIPT_ID = "script-candidate-linux-fixture";
const OBSERVER_ID = "observer-candidate-linux-fixture";
const SCRIPT_CONTENT_HASH = "c".repeat(64);
const SPEC_HASH = candidateLinuxPostExploitSpecificationHash({
  exploitOutcomeObserverSpecId: OBSERVER_ID,
  scriptArtifactId: SCRIPT_ID,
  scriptContentHash: SCRIPT_CONTENT_HASH,
  transportType: "candidate_runtime_session_v1",
  transportBindingId: BINDING_ID,
  transportOrigin: null,
  expectedPrincipal: "fixtureuser",
  expectedUid: 1001,
  declaredUserFlagPath: "/home/fixtureuser/user.txt",
});
const OPERATIONS = [
  "open",
  "observe_identity",
  "prove_user_flag_hash",
  "close",
  "privilege_escalation",
  "observe_root_identity",
  "prove_root_flag_hash",
  "cleanup",
] as const;
const TARGET_SCOPE = allAuthorizedIpCandidateLinuxTargetScope();
const BOUNDARY = Object.freeze({
  typedOperationsOnly: true,
  genericCommand: false,
  shell: false,
  argv: false,
  payload: false,
  credentials: false,
  exactTargetFromCanonicalAction: true,
  succeededAttackAttemptRequired: true,
  publicProvider: false,
});
const REAL_ADAPTER_BOUNDARY = Object.freeze({
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
});

const roots: string[] = [];
const brokers: CandidateLinuxTransportBrokerHandle[] = [];

afterEach(async () => {
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function fakeDatabase(): SqliteDatabase {
  return {
    prepare(sql: string) {
      return {
        get(...parameters: unknown[]) {
          if (
            sql.includes("FROM candidate_linux_post_exploit_specs WHERE id")
          ) {
            return {
              id: SPEC_ID,
              spec_hash: SPEC_HASH,
              transport_binding_id: BINDING_ID,
              transport_type: "candidate_runtime_session_v1",
              status: "active",
            };
          }
          if (
            sql.includes("FROM candidate_linux_post_exploit_specs spec")
            && sql.includes("JOIN script_artifacts script")
          ) {
            return {
              spec_hash: SPEC_HASH,
              transport_binding_id: BINDING_ID,
              transport_type: "candidate_runtime_session_v1",
              transport_origin: null,
              status: "active",
              observer_id: OBSERVER_ID,
              script_id: SCRIPT_ID,
              expected_principal: "fixtureuser",
              expected_uid: 1001,
              declared_user_flag_path: "/home/fixtureuser/user.txt",
              script_hash: SCRIPT_CONTENT_HASH,
              script_validation_state: "approved",
              observer_script_hash: SCRIPT_CONTENT_HASH,
              observer_status: "active",
            };
          }
          const exactFixtureRequest = parameters.includes(SPEC_ID)
            && parameters.includes(BINDING_ID)
            && parameters.includes("session-1")
            && parameters.includes("10.129.39.191");
          if (
            exactFixtureRequest
            && (
              sql.includes("FROM actions action")
              || sql.includes("FROM session_artifacts session")
            )
          ) {
            return { present: 1 };
          }
          return undefined;
        },
      };
    },
  } as unknown as SqliteDatabase;
}

async function rawBrokerRequest(
  socketPath: string,
  request: Readonly<Record<string, unknown>>,
): Promise<Record<string, unknown>> {
  return await new Promise((resolve, reject) => {
    const socket = createConnection({ path: socketPath });
    let response = "";
    socket.once("error", reject);
    socket.on("connect", () => socket.write(`${JSON.stringify(request)}\n`));
    socket.on("data", (chunk) => {
      response += chunk.toString("utf8");
      const newline = response.indexOf("\n");
      if (newline < 0) return;
      socket.destroy();
      resolve(JSON.parse(response.slice(0, newline)) as Record<string, unknown>);
    });
  });
}

async function fixture(options: Readonly<{
  candidateClass?: "disposable_local_fixture_v1"
    | "reviewed_real_candidate_v1";
  realTargetSupport?: boolean;
  adapterAttestationReady?: boolean;
  adapterAttestationInvalid?: boolean;
}> = {}): Promise<Readonly<{
  registry: CandidateLinuxTransportBindingRegistry;
  operations: string[];
  socketPath: string;
  manifestSha256: string;
}>> {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-candidate-transport-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const socketPath = join(root, "candidate.sock");
  const manifestPath = join(root, "manifest.json");
  const profilePath = join(root, "profile.json");
  const candidateClass =
    options.candidateClass ?? "disposable_local_fixture_v1";
  const realTargetSupport = options.realTargetSupport ?? false;
  const profileBytes = `${JSON.stringify({
    candidateClass,
    realTargetSupport,
  })}\n`;
  writeFileSync(profilePath, profileBytes, { mode: 0o600 });
  const profileSha256 = createHash("sha256")
    .update(profileBytes)
    .digest("hex");
  const brokerExecutablePath = "/bin/true";
  const manifest = {
    schemaVersion: CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
    bundleVersion: "fixture-1",
    broker: {
      executablePath: brokerExecutablePath,
      executableSha256: sha256File(brokerExecutablePath),
      socketPath,
      socketGid: process.getgid?.() ?? 0,
      protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
    },
    boundary: BOUNDARY,
    bindings: [{
      bindingId: BINDING_ID,
      postExploitSpecId: SPEC_ID,
      postExploitSpecSha256: SPEC_HASH,
      candidateClass,
      handlerProfilePath: profilePath,
      handlerProfileSha256: profileSha256,
      realTargetSupport,
      targetScope: TARGET_SCOPE,
      operations: OPERATIONS,
    }],
  };
  const bytes = `${JSON.stringify(manifest)}\n`;
  writeFileSync(manifestPath, bytes, { mode: 0o600 });
  const manifestSha256 = createHash("sha256").update(bytes).digest("hex");
  const operations: string[] = [];
  const loadedManifest = loadTrustedCandidateLinuxTransportBindingManifest({
    path: manifestPath,
    trustRoot: root,
    expectedSha256: manifestSha256,
    allowedOwnerUids: [process.getuid?.() ?? 0],
  });
  const registry = new CandidateLinuxTransportBindingRegistry({
    database: fakeDatabase(),
    loadedManifest,
    now: () => new Date("2026-07-23T12:01:00.000Z"),
  });
  brokers.push(await startCandidateLinuxTransportBroker({
    manifest: loadedManifest.value,
    manifestSha256,
    authorizer: registry,
    now: () => new Date("2026-07-23T12:00:00.000Z"),
    attestationTtlMs: 5 * 60_000,
    handlers: [{
      bindingId: BINDING_ID,
      postExploitSpecId: SPEC_ID,
      candidateClass,
      handlerProfileSha256: profileSha256,
      realTargetSupport,
      targetScope: TARGET_SCOPE,
      ...(options.adapterAttestationReady
        ? {
            async attest() {
              if (options.adapterAttestationInvalid) {
                return Object.freeze({ methodNameOnly: true });
              }
              const unsigned = {
                schemaVersion:
                  "ti-scale.reviewed-real-candidate-linux-adapter-attestation.v1",
                protocolVersion:
                  "ti-scale.reviewed-real-candidate-linux-adapter.v1",
                profileSha256,
                adapterExecutableSha256: "d".repeat(64),
                bindingId: BINDING_ID,
                postExploitSpecId: SPEC_ID,
                candidateClass: "reviewed_real_candidate_v1" as const,
                realTargetSupport: true as const,
                targetScope: TARGET_SCOPE,
                operations: OPERATIONS,
                boundary: REAL_ADAPTER_BOUNDARY,
                observedAt: "2026-07-23T12:00:00.000Z",
                expiresAt: "2026-07-23T12:01:00.000Z",
              };
              return Object.freeze({
                ...unsigned,
                receiptSha256: digestCanonicalJson(
                  unsigned,
                  { maxBytes: 64 * 1024, maxDepth: 16 },
                ).sha256,
              });
            },
          }
        : {}),
      async handle(request) {
        operations.push(request.operation);
        expect(["command", "argv", "shell", "payload", "credentials"].some(
          (key) => Object.hasOwn(request, key),
        )).toBe(false);
        return Object.freeze({
          operation: request.operation,
          accepted: true,
        });
      },
    }],
  }));
  await registry.attest();
  return { registry, operations, socketPath, manifestSha256 };
}

describe("CandidateLinuxTransportBindingRegistry Unix-socket boundary", () => {
  test("attests and carries only the fixed open-to-cleanup sequence", async () => {
    const { registry, operations } = await fixture();
    expect(registry.readiness().status).toBe("ready");
    expect(registry.readiness()).toMatchObject({
      readinessScope: "production_path_proof_only",
      missionExecutionReady: false,
      bindingCapabilities: [{
        bindingId: BINDING_ID,
        candidateClass: "disposable_local_fixture_v1",
        realTargetSupport: false,
      }],
    });
    expect(registry.missionExecutionReady()).toBe(false);
    const common = {
      transportBindingId: BINDING_ID,
      postExploitSpecId: SPEC_ID,
      sessionArtifactId: "session-1",
      exactTarget: "10.129.39.191",
    };
    await registry.invoke({ operation: "open", ...common }, new AbortController().signal);
    await registry.invoke(
      { operation: "observe_identity", ...common },
      new AbortController().signal,
    );
    await registry.invoke({
      operation: "prove_user_flag_hash",
      ...common,
      declaredPath: "/home/fixtureuser/user.txt",
    }, new AbortController().signal);
    const privileged = {
      ...common,
      candidateBindingHash: "b".repeat(64),
      leaseFencingToken: 1,
      actionId: "action-1",
    };
    await registry.invoke(
      { operation: "privilege_escalation", ...privileged },
      new AbortController().signal,
    );
    await registry.invoke(
      { operation: "observe_root_identity", ...privileged },
      new AbortController().signal,
    );
    await registry.invoke({
      operation: "prove_root_flag_hash",
      ...privileged,
      declaredPath: "/root/root.txt",
    }, new AbortController().signal);
    await registry.invoke({
      operation: "cleanup",
      ...common,
      candidateBindingHash: "b".repeat(64),
      leaseFencingToken: 1,
      reason: "completed",
    }, new AbortController().signal);
    expect(operations).toEqual([
      "open",
      "observe_identity",
      "prove_user_flag_hash",
      "privilege_escalation",
      "observe_root_identity",
      "prove_root_flag_hash",
      "cleanup",
    ]);
  });

  test("requires a live real-adapter attestation in addition to the reviewed binding label", async () => {
    const disposable = await fixture();
    expect(disposable.registry.readiness()).toMatchObject({
      status: "ready",
      readinessScope: "production_path_proof_only",
      missionExecutionReady: false,
    });
    expect(disposable.registry.missionExecutionReady()).toBe(false);

    const reviewed = await fixture({
      candidateClass: "reviewed_real_candidate_v1",
      realTargetSupport: true,
      adapterAttestationReady: true,
    });
    expect(reviewed.registry.readiness()).toMatchObject({
      status: "ready",
      readinessScope: "reviewed_real_candidate",
      missionExecutionReady: true,
      bindingCapabilities: [{
        bindingId: BINDING_ID,
        candidateClass: "reviewed_real_candidate_v1",
        realTargetSupport: true,
      }],
    });
    expect(reviewed.registry.missionExecutionReady()).toBe(true);

    await expect(fixture({
      candidateClass: "reviewed_real_candidate_v1",
      realTargetSupport: true,
      adapterAttestationReady: true,
      adapterAttestationInvalid: true,
    })).rejects.toThrow(
      "reviewed real-candidate adapter attestation",
    );
  });

  test("a restarted registry is blocked until it re-attests", async () => {
    const first = await fixture();
    const restarted = new CandidateLinuxTransportBindingRegistry(
      // Preserve the exact immutable deployment and DB bindings; attestation is
      // deliberately process-local and must be refreshed after restart.
      (first.registry as unknown as {
        options: ConstructorParameters<typeof CandidateLinuxTransportBindingRegistry>[0];
      }).options,
    );
    expect(restarted.readiness().status).toBe("blocked");
    await restarted.attest();
    expect(restarted.readiness().status).toBe("ready");
  });

  test("never reports readiness when the canonical candidate spec is missing or stale", async () => {
    const first = await fixture();
    const options = (first.registry as unknown as {
      options: ConstructorParameters<typeof CandidateLinuxTransportBindingRegistry>[0];
    }).options;
    const missing = new CandidateLinuxTransportBindingRegistry({
      ...options,
      database: {
        prepare() {
          return { get: () => undefined };
        },
      } as unknown as SqliteDatabase,
    });
    expect(missing.readiness()).toMatchObject({
      status: "blocked",
      code: "candidate_linux_transport_unavailable",
    });
    await expect(missing.attest()).rejects.toThrow(
      "active hash-matched candidate specification",
    );

    const stale = new CandidateLinuxTransportBindingRegistry({
      ...options,
      database: {
        prepare() {
          return {
            get: () => ({
              id: SPEC_ID,
              spec_hash: "f".repeat(64),
              transport_binding_id: BINDING_ID,
              transport_type: "candidate_runtime_session_v1",
              status: "active",
            }),
          };
        },
      } as unknown as SqliteDatabase,
    });
    expect(stale.readiness().status).toBe("blocked");
    await expect(stale.attest()).rejects.toThrow(
      "active hash-matched candidate specification",
    );
  });

  test("cancels a pending typed socket request", async () => {
    const { registry } = await fixture();
    const controller = new AbortController();
    controller.abort();
    await expect(registry.invoke({
      operation: "open",
      transportBindingId: BINDING_ID,
      postExploitSpecId: SPEC_ID,
      sessionArtifactId: "session-1",
      exactTarget: "10.129.39.191",
    }, controller.signal)).rejects.toThrow("cancelled");
  });

  test("the broker independently rejects unreviewed fields and canonical drift", async () => {
    const {
      registry,
      operations,
      socketPath,
      manifestSha256,
    } = await fixture();
    const envelope = (request: Readonly<Record<string, unknown>>) => ({
      protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
      bindingManifestSha256: manifestSha256,
      request,
    });
    const extraField = await rawBrokerRequest(socketPath, envelope({
      operation: "open",
      transportBindingId: BINDING_ID,
      postExploitSpecId: SPEC_ID,
      sessionArtifactId: "session-1",
      exactTarget: "10.129.39.191",
      command: "id",
    }));
    expect(extraField.ok).toBe(false);
    expect(operations).toEqual([]);

    const staleSession = {
      operation: "open" as const,
      transportBindingId: BINDING_ID,
      postExploitSpecId: SPEC_ID,
      sessionArtifactId: "session-from-an-older-plan",
      exactTarget: "10.129.39.191",
    };
    await expect(
      registry.invoke(staleSession, new AbortController().signal),
    ).rejects.toThrow("current signed action");
    const bypassAttempt = await rawBrokerRequest(
      socketPath,
      envelope(staleSession),
    );
    expect(bypassAttempt.ok).toBe(false);
    expect(operations).toEqual([]);
  });
});

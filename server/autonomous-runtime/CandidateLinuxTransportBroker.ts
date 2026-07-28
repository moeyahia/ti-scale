import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
} from "node:fs";
import { createServer, isIP, type Server, type Socket } from "node:net";
import {
  digestCanonicalJson,
} from "../mcp";
import {
  CANDIDATE_LINUX_TRANSPORT_ATTESTATION_SCHEMA_VERSION,
  CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
  type CandidateLinuxTransportBindingManifest,
  type CandidateLinuxTransportCanonicalAuthorizer,
  type CandidateLinuxTransportRequest,
} from "./CandidateLinuxTransportBindingRegistry";

const MAXIMUM_REQUEST_BYTES = 64 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u;
const PRINCIPAL_PATH = /^\/home\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\/user\.txt$/u;
const REVIEWED_REAL_ADAPTER_ATTESTATION_SCHEMA_VERSION =
  "ti-scale.reviewed-real-candidate-linux-adapter-attestation.v1";
const REVIEWED_REAL_ADAPTER_PROTOCOL_VERSION =
  "ti-scale.reviewed-real-candidate-linux-adapter.v1";
const REVIEWED_REAL_ADAPTER_BOUNDARY = Object.freeze({
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

export interface CandidateLinuxTransportBindingHandler {
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly candidateClass:
    | "disposable_local_fixture_v1"
    | "reviewed_real_candidate_v1";
  readonly handlerProfileSha256: string;
  readonly realTargetSupport: boolean;
  /**
   * Real candidate profiles may accept a current-run specification cloned
   * from their exact source specification. The database authorizer validates
   * that immutable derivation before this predicate is consulted.
   */
  acceptsPostExploitSpecId?(postExploitSpecId: string): boolean;
  /**
   * A reviewed real-target handler must prove its separately installed,
   * hash-pinned candidate adapter is live before the broker may attest the
   * binding. Disposable proof handlers deliberately omit this method.
   */
  attest?(signal: AbortSignal): Promise<unknown>;
  /**
   * Candidate-specific implementation compiled into the broker deployment.
   * The host passes only a closed typed request parsed below. It can never
   * receive command text, argv, shell, payload, credentials, or a target
   * supplied outside the canonical runtime action.
   */
  handle(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown>;
}

export interface CandidateLinuxTransportBrokerHandle {
  readonly socketPath: string;
  close(): Promise<void>;
}

function plain(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (
    actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])
  ) {
    throw new TypeError(`${label} contains an unreviewed field`);
  }
}

function id(value: unknown, label: string): string {
  if (typeof value !== "string" || !ID.test(value)) {
    throw new TypeError(`${label} must be a stable ID`);
  }
  return value;
}

function hash(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256`);
  }
  return value;
}

function target(value: unknown): string {
  if (typeof value !== "string" || isIP(value) === 0) {
    throw new TypeError("exactTarget must be one canonical IP literal");
  }
  return value;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw new TypeError(`${label} must be a positive integer`);
  }
  return Number(value);
}

function parseRequest(value: unknown): CandidateLinuxTransportRequest {
  const request = plain(value, "candidate request");
  const common = [
    "exactTarget",
    "operation",
    "postExploitSpecId",
    "sessionArtifactId",
    "transportBindingId",
  ];
  const operation = request.operation;
  if (
    operation === "open"
    || operation === "observe_identity"
    || operation === "close"
  ) {
    exactKeys(request, common, "candidate session request");
  } else if (operation === "prove_user_flag_hash") {
    exactKeys(
      request,
      [...common, "declaredPath"],
      "candidate user proof request",
    );
    if (
      typeof request.declaredPath !== "string"
      || !PRINCIPAL_PATH.test(request.declaredPath)
    ) {
      throw new TypeError("declaredPath is not the reviewed user proof path");
    }
  } else if (
    operation === "privilege_escalation"
    || operation === "observe_root_identity"
  ) {
    exactKeys(request, [
      ...common,
      "actionId",
      "candidateBindingHash",
      "leaseFencingToken",
    ], "candidate privilege request");
  } else if (operation === "prove_root_flag_hash") {
    exactKeys(request, [
      ...common,
      "actionId",
      "candidateBindingHash",
      "declaredPath",
      "leaseFencingToken",
    ], "candidate root proof request");
    if (request.declaredPath !== "/root/root.txt") {
      throw new TypeError("declaredPath is not /root/root.txt");
    }
  } else if (operation === "cleanup") {
    exactKeys(request, [
      ...common,
      "candidateBindingHash",
      "leaseFencingToken",
      "reason",
    ], "candidate cleanup request");
    if (
      typeof request.reason !== "string"
      || request.reason !== request.reason.trim()
      || request.reason.length < 1
      || request.reason.length > 300
      || /[\u0000-\u001F\u007F]/u.test(request.reason)
    ) {
      throw new TypeError("cleanup reason is invalid");
    }
  } else {
    throw new TypeError("candidate operation is unsupported");
  }
  id(request.transportBindingId, "transportBindingId");
  id(request.postExploitSpecId, "postExploitSpecId");
  id(request.sessionArtifactId, "sessionArtifactId");
  target(request.exactTarget);
  if ("candidateBindingHash" in request) {
    hash(request.candidateBindingHash, "candidateBindingHash");
    positiveInteger(request.leaseFencingToken, "leaseFencingToken");
  }
  if ("actionId" in request) id(request.actionId, "actionId");
  return Object.freeze({ ...request }) as CandidateLinuxTransportRequest;
}

function safeError(error: unknown): Readonly<{
  readonly code: string;
  readonly message: string;
}> {
  const message = error instanceof Error
    ? error.message
    : "Candidate Linux transport rejected the request";
  return Object.freeze({
    code: "candidate_linux_transport_request_rejected",
    message: message.replace(/[\u0000-\u001F\u007F]/gu, " ")
      .replace(/\s+/gu, " ").trim().slice(0, 500),
  });
}

function writeEnvelope(socket: Socket, envelope: unknown): void {
  socket.end(`${JSON.stringify(envelope)}\n`);
}

function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

/**
 * A method named `attest` is not sufficient evidence. The broker validates
 * the candidate adapter's complete, hash-bound receipt before its own
 * attestation can make the runtime ready.
 */
function validateReviewedRealAdapterAttestation(
  rawValue: unknown,
  binding: CandidateLinuxTransportBindingManifest["bindings"][number],
  now: Date,
): void {
  const raw = plain(rawValue, "reviewed real-candidate adapter attestation");
  exactKeys(raw, [
    "adapterExecutableSha256",
    "bindingId",
    "boundary",
    "candidateClass",
    "expiresAt",
    "observedAt",
    "operations",
    "postExploitSpecId",
    "profileSha256",
    "protocolVersion",
    "realTargetSupport",
    "receiptSha256",
    "schemaVersion",
  ], "reviewed real-candidate adapter attestation");
  const boundary = plain(
    raw.boundary,
    "reviewed real-candidate adapter boundary",
  );
  exactKeys(
    boundary,
    Object.keys(REVIEWED_REAL_ADAPTER_BOUNDARY),
    "reviewed real-candidate adapter boundary",
  );
  const operations = raw.operations;
  const observedAt = raw.observedAt;
  const expiresAt = raw.expiresAt;
  const observed = validTimestamp(observedAt)
    ? Date.parse(observedAt)
    : Number.NaN;
  const expires = validTimestamp(expiresAt)
    ? Date.parse(expiresAt)
    : Number.NaN;
  const unsigned = {
    schemaVersion: raw.schemaVersion,
    protocolVersion: raw.protocolVersion,
    profileSha256: raw.profileSha256,
    adapterExecutableSha256: raw.adapterExecutableSha256,
    bindingId: raw.bindingId,
    postExploitSpecId: raw.postExploitSpecId,
    candidateClass: raw.candidateClass,
    realTargetSupport: raw.realTargetSupport,
    operations,
    boundary: raw.boundary,
    observedAt,
    expiresAt,
  };
  if (
    raw.schemaVersion !== REVIEWED_REAL_ADAPTER_ATTESTATION_SCHEMA_VERSION
    || raw.protocolVersion !== REVIEWED_REAL_ADAPTER_PROTOCOL_VERSION
    || raw.profileSha256 !== binding.handlerProfileSha256
    || raw.bindingId !== binding.bindingId
    || raw.postExploitSpecId !== binding.postExploitSpecId
    || raw.candidateClass !== "reviewed_real_candidate_v1"
    || raw.realTargetSupport !== true
    || typeof raw.adapterExecutableSha256 !== "string"
    || !SHA256.test(raw.adapterExecutableSha256)
    || !Array.isArray(operations)
    || operations.length !== binding.operations.length
    || operations.some(
      (operation, index) => operation !== binding.operations[index],
    )
    || Object.entries(REVIEWED_REAL_ADAPTER_BOUNDARY).some(
      ([key, value]) => boundary[key] !== value,
    )
    || !Number.isFinite(observed)
    || !Number.isFinite(expires)
    || observed < now.getTime() - 60_000
    || observed > now.getTime() + 5_000
    || expires <= now.getTime()
    || expires <= observed
    || expires > observed + 5 * 60_000
    || typeof raw.receiptSha256 !== "string"
    || !SHA256.test(raw.receiptSha256)
    || digestCanonicalJson(
      unsigned,
      { maxBytes: 64 * 1024, maxDepth: 16 },
    ).sha256 !== raw.receiptSha256
  ) {
    throw new Error(
      "The reviewed real-candidate adapter attestation is invalid",
    );
  }
}

/**
 * Strict production broker host. Candidate implementations are injected by
 * exact binding/spec identity at process composition time; the socket protocol
 * itself provides no dynamic module, command, shell, argv, path, payload,
 * credential, or arbitrary-target surface.
 */
export async function startCandidateLinuxTransportBroker(input: Readonly<{
  manifest: CandidateLinuxTransportBindingManifest;
  /** Exact source-file hash also pinned by the runtime trusted-file receipt. */
  manifestSha256: string;
  /**
   * Mandatory database-backed authorization. The broker repeats the canonical
   * action/plan/contract/AttackAttempt/session-fence check so direct socket
   * clients cannot bypass the runtime-side gate.
   */
  authorizer: CandidateLinuxTransportCanonicalAuthorizer;
  handlers: readonly CandidateLinuxTransportBindingHandler[];
  now?: () => Date;
  attestationTtlMs?: number;
}>): Promise<CandidateLinuxTransportBrokerHandle> {
  const now = input.now ?? (() => new Date());
  const ttl = input.attestationTtlMs ?? 60_000;
  if (!Number.isSafeInteger(ttl) || ttl < 1_000 || ttl > 5 * 60_000) {
    throw new RangeError("Candidate broker attestation TTL is outside its bound");
  }
  hash(input.manifestSha256, "manifestSha256");
  if (existsSync(input.manifest.broker.socketPath)) {
    throw new Error(
      "Candidate broker socket path already exists; reconcile its owner instead of deleting it",
    );
  }
  const handlers = new Map(
    input.handlers.map((handler) => [handler.bindingId, handler]),
  );
  if (
    handlers.size !== input.handlers.length
    || handlers.size !== input.manifest.bindings.length
    || input.manifest.bindings.some((binding) =>
      handlers.get(binding.bindingId)?.postExploitSpecId
        !== binding.postExploitSpecId
      || handlers.get(binding.bindingId)?.candidateClass
        !== binding.candidateClass
      || handlers.get(binding.bindingId)?.handlerProfileSha256
        !== binding.handlerProfileSha256
      || handlers.get(binding.bindingId)?.realTargetSupport
        !== binding.realTargetSupport)
  ) {
    throw new Error(
      "Candidate broker handlers do not exactly match the pinned manifest",
    );
  }
  if (input.manifest.bindings.some((binding) =>
    binding.candidateClass === "reviewed_real_candidate_v1"
    && typeof handlers.get(binding.bindingId)?.attest !== "function")) {
    throw new Error(
      "Every reviewed real-candidate binding requires a live adapter attestation",
    );
  }
  const manifestSha256 = input.manifestSha256;
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.setTimeout(5_000);
    const controller = new AbortController();
    let body = "";
    let handled = false;
    const cancel = () => controller.abort(
      new Error("Candidate broker client disconnected"),
    );
    socket.once("close", cancel);
    socket.once("error", cancel);
    socket.once("timeout", () => socket.destroy(
      new Error("Candidate broker request timed out"),
    ));
    socket.on("data", (chunk) => {
      if (handled) return;
      body += chunk.toString("utf8");
      if (Buffer.byteLength(body, "utf8") > MAXIMUM_REQUEST_BYTES) {
        handled = true;
        writeEnvelope(socket, {
          ok: false,
          error: safeError(new Error("Candidate broker request exceeded its bound")),
        });
        return;
      }
      const newline = body.indexOf("\n");
      if (newline < 0) return;
      handled = true;
      void (async () => {
        try {
          const envelope = plain(
            JSON.parse(body.slice(0, newline)) as unknown,
            "candidate broker envelope",
          );
          if (envelope.operation === "attest") {
            exactKeys(
              envelope,
              ["manifestSha256", "operation", "protocolVersion"],
              "candidate broker attestation request",
            );
            if (
              envelope.protocolVersion
                !== CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION
              || envelope.manifestSha256 !== manifestSha256
            ) {
              throw new Error("Candidate broker attestation identity mismatch");
            }
            for (const binding of input.manifest.bindings) {
              if (binding.candidateClass !== "reviewed_real_candidate_v1") {
                continue;
              }
              const handler = handlers.get(binding.bindingId);
              if (!handler?.attest) {
                throw new Error(
                  "A reviewed real-candidate adapter attestation is missing",
                );
              }
              validateReviewedRealAdapterAttestation(
                await handler.attest(controller.signal),
                binding,
                now(),
              );
            }
            const observedAt = now();
            const unsigned = {
              schemaVersion:
                CANDIDATE_LINUX_TRANSPORT_ATTESTATION_SCHEMA_VERSION,
              protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
              manifestSha256,
              brokerExecutableSha256:
                input.manifest.broker.executableSha256,
              bindingIds: input.manifest.bindings.map(
                ({ bindingId }) => bindingId,
              ),
              bindingCapabilities: input.manifest.bindings.map((binding) => ({
                bindingId: binding.bindingId,
                candidateClass: binding.candidateClass,
                realTargetSupport: binding.realTargetSupport,
              })),
              boundary: input.manifest.boundary,
              grantsMissionExecution: false as const,
              observedAt: observedAt.toISOString(),
              expiresAt: new Date(
                observedAt.getTime() + ttl,
              ).toISOString(),
            };
            writeEnvelope(socket, {
              ok: true,
              result: {
                ...unsigned,
                receiptSha256: digestCanonicalJson(
                  unsigned,
                  { maxBytes: 64 * 1024, maxDepth: 16 },
                ).sha256,
              },
            });
            return;
          }
          exactKeys(
            envelope,
            ["bindingManifestSha256", "protocolVersion", "request"],
            "candidate broker invocation envelope",
          );
          if (
            envelope.protocolVersion
              !== CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION
            || envelope.bindingManifestSha256 !== manifestSha256
          ) {
            throw new Error("Candidate broker invocation identity mismatch");
          }
          const request = parseRequest(envelope.request);
          input.authorizer.authorize(request);
          const handler = handlers.get(request.transportBindingId);
          if (
            !handler
            || (
              handler.postExploitSpecId !== request.postExploitSpecId
              && handler.acceptsPostExploitSpecId?.(
                request.postExploitSpecId,
              ) !== true
            )
          ) {
            throw new Error(
              "Candidate broker request does not match a pinned binding",
            );
          }
          const result = await handler.handle(request, controller.signal);
          writeEnvelope(socket, { ok: true, result });
        } catch (error) {
          writeEnvelope(socket, { ok: false, error: safeError(error) });
        }
      })();
    });
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(input.manifest.broker.socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  chmodSync(input.manifest.broker.socketPath, 0o660);
  chownSync(input.manifest.broker.socketPath, -1, input.manifest.broker.socketGid);
  const socket = lstatSync(input.manifest.broker.socketPath);
  if (
    !socket.isSocket()
    || socket.gid !== input.manifest.broker.socketGid
    || (socket.mode & 0o007) !== 0
  ) {
    server.close();
    throw new Error("Candidate broker socket ownership could not be established");
  }
  return Object.freeze({
    socketPath: input.manifest.broker.socketPath,
    async close() {
      for (const client of sockets) client.destroy();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  });
}

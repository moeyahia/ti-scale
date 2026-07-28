import { request as httpRequest } from "node:http";
import { isIP } from "node:net";
import { digestCanonicalJson } from "../mcp";

export const AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE =
  "autonomous_linux_privilege_escalation_v1" as const;
export const AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS =
  "privilege_escalation" as const;
export const AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE =
  "autonomous_linux_root_flag_proof_v1" as const;
export const AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_CLASS =
  "data_access_impact_validation" as const;
export const AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE =
  "autonomous_linux_session_cleanup_v1" as const;
export const AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS =
  "cleanup_restoration" as const;

export const AUTONOMOUS_LINUX_PRIVILEGE_ACTION_ARGUMENTS_SCHEMA_VERSION =
  "ti-scale.autonomous-linux-privilege-action-arguments.v1" as const;
export const LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION =
  "ti-scale.loopback-linux-privilege-ack.v1" as const;
export const LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION =
  "ti-scale.loopback-linux-root-identity.v1" as const;
export const LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION =
  "ti-scale.loopback-linux-root-flag-proof.v1" as const;
export const LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION =
  "ti-scale.loopback-linux-cleanup-ack.v1" as const;

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_RESPONSE_BYTES = 32 * 1_024;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 15_000;
const ROOT_FLAG_PATH = "/root/root.txt";

export type AutonomousLinuxPrivilegeContinuationActionType =
  | typeof AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE
  | typeof AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
  | typeof AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE;

export interface AutonomousLinuxPrivilegeActionArguments
extends Readonly<Record<string, unknown>> {
  readonly schemaVersion:
    typeof AUTONOMOUS_LINUX_PRIVILEGE_ACTION_ARGUMENTS_SCHEMA_VERSION;
  readonly sessionArtifactId: string;
  readonly postExploitSpecId: string;
  readonly declaredPath?: typeof ROOT_FLAG_PATH;
}

export interface CandidateLinuxPrivilegeSessionBinding {
  readonly sessionArtifactId: string;
  readonly postExploitSpecId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly exactTarget: string;
  readonly candidateBindingHash: string;
  readonly leaseFencingToken: number;
  readonly transportType:
    | "loopback_http_session_v1"
    | "candidate_runtime_session_v1";
  readonly transportBindingId: string;
  readonly transportOrigin?: string;
  readonly privilegePath: "/ti-scale/session/privilege-escalation";
  readonly rootIdentityPath: "/ti-scale/session/root-identity";
  readonly rootFlagProofPath: "/ti-scale/session/root-flag-proof";
  readonly cleanupPath: "/ti-scale/session/cleanup";
  readonly declaredRootFlagPath: typeof ROOT_FLAG_PATH;
}

export interface LoopbackLinuxPrivilegeAck {
  readonly schemaVersion: typeof LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION;
  readonly sessionArtifactId: string;
  readonly accepted: true;
  readonly observedAt: string;
  readonly receiptSha256: string;
}

export interface IndependentRootIdentityObservation {
  readonly schemaVersion: typeof LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION;
  readonly sessionArtifactId: string;
  readonly principal: "root";
  readonly uid: 0;
  readonly gid: 0;
  readonly groups: readonly string[];
  readonly observedAt: string;
  readonly observationSha256: string;
}

export interface RootFlagHashProof {
  readonly schemaVersion: typeof LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION;
  readonly sessionArtifactId: string;
  readonly declaredPath: typeof ROOT_FLAG_PATH;
  readonly contentSha256: string;
  readonly byteSize: number;
  readonly observedAt: string;
  readonly proofSha256: string;
}

export interface LoopbackLinuxCleanupAck {
  readonly schemaVersion: typeof LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION;
  readonly sessionArtifactId: string;
  readonly closed: true;
  readonly observedAt: string;
  readonly receiptSha256: string;
}

export interface CandidateLinuxPrivilegeContinuationAdapterPort {
  requestPrivilegeEscalation(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<LoopbackLinuxPrivilegeAck>;
  observeRootIdentity(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<IndependentRootIdentityObservation>;
  proveRootFlag(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<RootFlagHashProof>;
  cleanup(
    binding: CandidateLinuxPrivilegeSessionBinding,
    reason: string,
    signal: AbortSignal,
  ): Promise<LoopbackLinuxCleanupAck>;
}

export type CandidateRuntimeLinuxPrivilegeRequest =
  | Readonly<{
      operation: "privilege_escalation";
      transportBindingId: string;
      postExploitSpecId: string;
      sessionArtifactId: string;
      exactTarget: string;
      candidateBindingHash: string;
      leaseFencingToken: number;
      actionId: string;
    }>
  | Readonly<{
      operation: "observe_root_identity";
      transportBindingId: string;
      postExploitSpecId: string;
      sessionArtifactId: string;
      exactTarget: string;
      candidateBindingHash: string;
      leaseFencingToken: number;
      actionId: string;
    }>
  | Readonly<{
      operation: "prove_root_flag_hash";
      transportBindingId: string;
      postExploitSpecId: string;
      sessionArtifactId: string;
      exactTarget: string;
      candidateBindingHash: string;
      leaseFencingToken: number;
      actionId: string;
      declaredPath: typeof ROOT_FLAG_PATH;
    }>
  | Readonly<{
      operation: "cleanup";
      transportBindingId: string;
      postExploitSpecId: string;
      sessionArtifactId: string;
      exactTarget: string;
      candidateBindingHash: string;
      leaseFencingToken: number;
      reason: string;
    }>;

/**
 * Production-facing candidate transport. Implementations are separately
 * attested and map one reviewed transportBindingId to one exact candidate.
 * The schema deliberately has no command, argv, shell, payload, credential,
 * arbitrary path, or file-content field.
 */
export interface CandidateRuntimeLinuxPrivilegeTransport {
  invoke(
    request: CandidateRuntimeLinuxPrivilegeRequest,
    signal: AbortSignal,
  ): Promise<unknown>;
}

export class CandidateLinuxPrivilegeContinuationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "CandidateLinuxPrivilegeContinuationError";
  }
}

function fail(code: string, message: string): never {
  throw new CandidateLinuxPrivilegeContinuationError(code, message);
}

function plain(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function stableId(value: unknown, label: string): string {
  if (typeof value !== "string" || !ID.test(value)) {
    return fail(
      "autonomous_linux_privilege_arguments_invalid",
      `${label} is not a valid stable identifier.`,
    );
  }
  return value;
}

function sha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    return fail(
      "autonomous_linux_privilege_arguments_invalid",
      `${label} is not a lowercase SHA-256 digest.`,
    );
  }
  return value;
}

export function parseAutonomousLinuxPrivilegeActionArguments(
  actionType: AutonomousLinuxPrivilegeContinuationActionType,
  value: Readonly<Record<string, unknown>>,
): AutonomousLinuxPrivilegeActionArguments {
  const expected = [
    "schemaVersion",
    "sessionArtifactId",
    "postExploitSpecId",
    ...(actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
      ? ["declaredPath"]
      : []),
  ];
  if (!exactKeys(value, expected)
    || value.schemaVersion
      !== AUTONOMOUS_LINUX_PRIVILEGE_ACTION_ARGUMENTS_SCHEMA_VERSION) {
    return fail(
      "autonomous_linux_privilege_arguments_invalid",
      "The candidate-bound Linux action arguments are unversioned, widened, or malformed.",
    );
  }
  if (actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
    && value.declaredPath !== ROOT_FLAG_PATH) {
    return fail(
      "autonomous_linux_root_flag_path_invalid",
      "The disposable root proof accepts exactly /root/root.txt.",
    );
  }
  return Object.freeze({
    schemaVersion: AUTONOMOUS_LINUX_PRIVILEGE_ACTION_ARGUMENTS_SCHEMA_VERSION,
    sessionArtifactId: stableId(value.sessionArtifactId, "SessionArtifact ID"),
    postExploitSpecId: stableId(value.postExploitSpecId, "Post-exploit spec ID"),
    ...(actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
      ? { declaredPath: ROOT_FLAG_PATH }
      : {}),
  });
}

export function createAutonomousLinuxPrivilegeActionArguments(input: Readonly<{
  actionType: AutonomousLinuxPrivilegeContinuationActionType;
  sessionArtifactId: string;
  postExploitSpecId: string;
}>): AutonomousLinuxPrivilegeActionArguments {
  return parseAutonomousLinuxPrivilegeActionArguments(input.actionType, {
    schemaVersion: AUTONOMOUS_LINUX_PRIVILEGE_ACTION_ARGUMENTS_SCHEMA_VERSION,
    sessionArtifactId: input.sessionArtifactId,
    postExploitSpecId: input.postExploitSpecId,
    ...(input.actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
      ? { declaredPath: ROOT_FLAG_PATH }
      : {}),
  });
}

function reviewedOrigin(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return fail(
      "autonomous_linux_session_origin_invalid",
      "The candidate session transport origin is invalid.",
    );
  }
  if (parsed.protocol !== "http:"
    || !parsed.port
    || parsed.username
    || parsed.password
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash
    || !(
      parsed.hostname === "127.0.0.1"
      || parsed.hostname === "[::1]"
      || parsed.hostname === "::1"
    )
    || (parsed.hostname === "127.0.0.1" && isIP(parsed.hostname) !== 4)
    || (
      parsed.hostname !== "127.0.0.1"
      && isIP(parsed.hostname.replace(/^\[|\]$/gu, "")) !== 6
    )) {
    return fail(
      "autonomous_linux_session_origin_not_loopback",
      "The candidate session adapter accepts only one explicit loopback HTTP origin.",
    );
  }
  return parsed;
}

function assertLoopbackBinding(
  binding: CandidateLinuxPrivilegeSessionBinding,
): string {
  if (binding.transportType !== "loopback_http_session_v1"
    || !binding.transportOrigin) {
    return fail(
      "autonomous_linux_loopback_privilege_binding_invalid",
      "The loopback privilege fixture requires one explicit loopback transport origin.",
    );
  }
  if (!binding.transportBindingId.trim()
    || binding.transportBindingId.length > 200) {
    return fail(
      "autonomous_linux_privilege_transport_binding_invalid",
      "The reviewed candidate transport binding ID is invalid.",
    );
  }
  reviewedOrigin(binding.transportOrigin);
  return binding.transportOrigin;
}

function assertRuntimeBinding(
  binding: CandidateLinuxPrivilegeSessionBinding,
): void {
  if (binding.transportType !== "candidate_runtime_session_v1"
    || binding.transportOrigin !== undefined
    || !binding.transportBindingId.trim()
    || binding.transportBindingId.length > 200) {
    return fail(
      "autonomous_linux_candidate_runtime_privilege_binding_invalid",
      "A production candidate privilege operation requires one reviewed runtime binding and cannot carry a network origin.",
    );
  }
}

function reviewedPath(
  value: string,
  expected:
    | CandidateLinuxPrivilegeSessionBinding["privilegePath"]
    | CandidateLinuxPrivilegeSessionBinding["rootIdentityPath"]
    | CandidateLinuxPrivilegeSessionBinding["rootFlagProofPath"]
    | CandidateLinuxPrivilegeSessionBinding["cleanupPath"],
): string {
  if (value !== expected) {
    return fail(
      "autonomous_linux_session_operation_path_invalid",
      `The candidate session operation must use the reviewed ${expected} path.`,
    );
  }
  return value;
}

function observedAt(value: unknown, label: string): string {
  if (typeof value !== "string"
    || !Number.isFinite(Date.parse(value))
    || value.length > 40) {
    return fail(
      "autonomous_linux_session_response_invalid",
      `${label} is not a bounded timestamp.`,
    );
  }
  return value;
}

function responseHash(
  response: Readonly<Record<string, unknown>>,
  hashField: string,
): string {
  const claimed = sha256(
    response[hashField],
    `Loopback ${hashField}`,
  );
  const material = { ...response };
  delete material[hashField];
  const computed = digestCanonicalJson(
    material,
    { maxBytes: MAX_RESPONSE_BYTES, maxDepth: 12 },
  ).sha256;
  if (claimed !== computed) {
    return fail(
      "autonomous_linux_session_response_hash_mismatch",
      "The loopback operation receipt failed its canonical integrity check.",
    );
  }
  return claimed;
}

async function readJsonResponse(
  response: NodeJS.ReadableStream,
  signal: AbortSignal,
): Promise<Readonly<Record<string, unknown>>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of response) {
    if (signal.aborted) {
      throw signal.reason instanceof Error
        ? signal.reason
        : new Error("Loopback operation cancelled");
    }
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      return fail(
        "autonomous_linux_session_response_too_large",
        "The loopback operation response exceeded its fixed 32 KiB bound.",
      );
    }
    chunks.push(bytes);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    if (!plain(parsed)) throw new Error("not an object");
    return parsed;
  } catch {
    return fail(
      "autonomous_linux_session_response_invalid",
      "The loopback operation returned malformed JSON.",
    );
  }
}

async function requestJson(input: Readonly<{
  origin: string;
  method: "GET" | "POST";
  path: string;
  body?: Readonly<Record<string, unknown>>;
  timeoutMs: number;
  signal: AbortSignal;
}>): Promise<Readonly<Record<string, unknown>>> {
  if (!Number.isSafeInteger(input.timeoutMs)
    || input.timeoutMs < MIN_TIMEOUT_MS
    || input.timeoutMs > MAX_TIMEOUT_MS) {
    return fail(
      "autonomous_linux_session_timeout_invalid",
      "The loopback operation timeout is outside its reviewed bound.",
    );
  }
  const origin = reviewedOrigin(input.origin);
  const body = input.body
    ? Buffer.from(digestCanonicalJson(
        input.body,
        { maxBytes: MAX_RESPONSE_BYTES, maxDepth: 12 },
      ).canonicalJson, "utf8")
    : undefined;
  return await new Promise<Readonly<Record<string, unknown>>>((resolve, reject) => {
    let settled = false;
    const request = httpRequest({
      protocol: origin.protocol,
      hostname: origin.hostname.replace(/^\[|\]$/gu, ""),
      port: Number(origin.port),
      method: input.method,
      path: input.path,
      headers: body
        ? {
            "content-type": "application/json",
            "content-length": String(body.byteLength),
            "cache-control": "no-store",
          }
        : { "cache-control": "no-store" },
      timeout: input.timeoutMs,
      signal: input.signal,
    }, async (response) => {
      try {
        if (response.statusCode !== 200
          || typeof response.headers["content-type"] !== "string"
          || !response.headers["content-type"].toLowerCase().startsWith(
            "application/json",
          )) {
          response.resume();
          return fail(
            "autonomous_linux_session_response_rejected",
            "The fixed loopback endpoint returned a non-success or non-JSON response.",
          );
        }
        const result = await readJsonResponse(response, input.signal);
        if (!settled) {
          settled = true;
          resolve(result);
        }
      } catch (error) {
        if (!settled) {
          settled = true;
          reject(error);
        }
      }
    });
    request.once("timeout", () => {
      request.destroy(new CandidateLinuxPrivilegeContinuationError(
        "autonomous_linux_session_timeout",
        "The fixed loopback operation exceeded its timeout.",
      ));
    });
    request.once("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    if (body) request.write(body);
    request.end();
  });
}

function commonRequest(
  binding: CandidateLinuxPrivilegeSessionBinding,
  actionId?: string,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    schemaVersion: "ti-scale.loopback-linux-session-operation.v1",
    sessionArtifactId: binding.sessionArtifactId,
    postExploitSpecId: binding.postExploitSpecId,
    missionId: binding.missionId,
    runId: binding.runId,
    exactTarget: binding.exactTarget,
    candidateBindingHash: binding.candidateBindingHash,
    leaseFencingToken: binding.leaseFencingToken,
    ...(actionId ? { actionId } : {}),
  });
}

/**
 * Candidate-specific transport for one disposable loopback Linux fixture.
 *
 * It intentionally exposes no command, shell, path, environment, upload, or
 * arbitrary request primitive. Escalation, independent identity observation,
 * one exact hash-only root proof, and cleanup are the complete API.
 */
export class LoopbackCandidateLinuxPrivilegeAdapter
implements CandidateLinuxPrivilegeContinuationAdapterPort {
  constructor(private readonly timeoutMs = 5_000) {
    if (!Number.isSafeInteger(timeoutMs)
      || timeoutMs < MIN_TIMEOUT_MS
      || timeoutMs > MAX_TIMEOUT_MS) {
      throw new RangeError("Loopback privilege adapter timeout is outside its reviewed bound");
    }
  }

  async requestPrivilegeEscalation(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<LoopbackLinuxPrivilegeAck> {
    const origin = assertLoopbackBinding(binding);
    const response = await requestJson({
      origin,
      method: "POST",
      path: reviewedPath(
        binding.privilegePath,
        "/ti-scale/session/privilege-escalation",
      ),
      body: Object.freeze({
        ...commonRequest(binding, actionId),
        operation: "privilege_escalation",
      }),
      timeoutMs: this.timeoutMs,
      signal,
    });
    const expected = [
      "schemaVersion",
      "sessionArtifactId",
      "accepted",
      "observedAt",
      "receiptSha256",
    ];
    if (!exactKeys(response, expected)
      || response.schemaVersion !== LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION
      || response.sessionArtifactId !== binding.sessionArtifactId
      || response.accepted !== true) {
      return fail(
        "autonomous_linux_privilege_ack_invalid",
        "The fixed privilege endpoint did not return the exact candidate-bound acknowledgement.",
      );
    }
    const normalized: LoopbackLinuxPrivilegeAck = {
      schemaVersion: LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
      sessionArtifactId: binding.sessionArtifactId,
      accepted: true as const,
      observedAt: observedAt(response.observedAt, "Privilege acknowledgement time"),
      receiptSha256: responseHash(response, "receiptSha256"),
    };
    return Object.freeze(normalized);
  }

  async observeRootIdentity(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<IndependentRootIdentityObservation> {
    const origin = assertLoopbackBinding(binding);
    const query = new URLSearchParams({
      sessionArtifactId: binding.sessionArtifactId,
      postExploitSpecId: binding.postExploitSpecId,
      candidateBindingHash: binding.candidateBindingHash,
      leaseFencingToken: String(binding.leaseFencingToken),
      actionId,
    });
    const response = await requestJson({
      origin,
      method: "GET",
      path: `${reviewedPath(
        binding.rootIdentityPath,
        "/ti-scale/session/root-identity",
      )}?${query.toString()}`,
      timeoutMs: this.timeoutMs,
      signal,
    });
    const expected = [
      "schemaVersion",
      "sessionArtifactId",
      "principal",
      "uid",
      "gid",
      "groups",
      "observedAt",
      "observationSha256",
    ];
    if (!exactKeys(response, expected)
      || response.schemaVersion !== LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION
      || response.sessionArtifactId !== binding.sessionArtifactId
      || response.principal !== "root"
      || response.uid !== 0
      || response.gid !== 0
      || !Array.isArray(response.groups)
      || response.groups.length < 1
      || response.groups.length > 32
      || response.groups.some((group) =>
        typeof group !== "string"
        || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/u.test(group))) {
      return fail(
        "autonomous_linux_root_identity_not_verified",
        "The independent identity endpoint did not prove the root principal with UID and GID zero.",
      );
    }
    const normalized: IndependentRootIdentityObservation = {
      schemaVersion: LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
      sessionArtifactId: binding.sessionArtifactId,
      principal: "root" as const,
      uid: 0 as const,
      gid: 0 as const,
      groups: Object.freeze([...new Set(response.groups as string[])]),
      observedAt: observedAt(response.observedAt, "Root identity observation time"),
      observationSha256: responseHash(response, "observationSha256"),
    };
    return Object.freeze(normalized);
  }

  async proveRootFlag(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<RootFlagHashProof> {
    const origin = assertLoopbackBinding(binding);
    if (binding.declaredRootFlagPath !== ROOT_FLAG_PATH) {
      return fail(
        "autonomous_linux_root_flag_path_invalid",
        "The canonical candidate spec does not declare exactly /root/root.txt.",
      );
    }
    const response = await requestJson({
      origin,
      method: "POST",
      path: reviewedPath(
        binding.rootFlagProofPath,
        "/ti-scale/session/root-flag-proof",
      ),
      body: Object.freeze({
        ...commonRequest(binding, actionId),
        operation: "root_flag_hash_proof",
        declaredPath: ROOT_FLAG_PATH,
        returnContent: false,
      }),
      timeoutMs: this.timeoutMs,
      signal,
    });
    const expected = [
      "schemaVersion",
      "sessionArtifactId",
      "declaredPath",
      "contentSha256",
      "byteSize",
      "observedAt",
      "proofSha256",
    ];
    if (!exactKeys(response, expected)
      || response.schemaVersion !== LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION
      || response.sessionArtifactId !== binding.sessionArtifactId
      || response.declaredPath !== ROOT_FLAG_PATH
      || !SHA256.test(String(response.contentSha256))
      || !Number.isSafeInteger(response.byteSize)
      || Number(response.byteSize) < 1
      || Number(response.byteSize) > 4_096) {
      return fail(
        "autonomous_linux_root_flag_proof_invalid",
        "The fixed root proof endpoint did not return one hash-only /root/root.txt receipt.",
      );
    }
    const normalized: RootFlagHashProof = {
      schemaVersion: LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
      sessionArtifactId: binding.sessionArtifactId,
      declaredPath: ROOT_FLAG_PATH,
      contentSha256: String(response.contentSha256),
      byteSize: Number(response.byteSize),
      observedAt: observedAt(response.observedAt, "Root flag proof time"),
      proofSha256: responseHash(response, "proofSha256"),
    };
    return Object.freeze(normalized);
  }

  async cleanup(
    binding: CandidateLinuxPrivilegeSessionBinding,
    reason: string,
    signal: AbortSignal,
  ): Promise<LoopbackLinuxCleanupAck> {
    const origin = assertLoopbackBinding(binding);
    const normalizedReason = reason
      .replace(/[\u0000-\u001F\u007F]/gu, " ")
      .trim().replace(/\s+/gu, " ").slice(0, 300);
    if (!normalizedReason) {
      return fail(
        "autonomous_linux_cleanup_reason_invalid",
        "A bounded cleanup reason is required.",
      );
    }
    const response = await requestJson({
      origin,
      method: "POST",
      path: reviewedPath(
        binding.cleanupPath,
        "/ti-scale/session/cleanup",
      ),
      body: Object.freeze({
        ...commonRequest(binding),
        operation: "cleanup",
        reason: normalizedReason,
      }),
      timeoutMs: this.timeoutMs,
      signal,
    });
    const expected = [
      "schemaVersion",
      "sessionArtifactId",
      "closed",
      "observedAt",
      "receiptSha256",
    ];
    if (!exactKeys(response, expected)
      || response.schemaVersion !== LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION
      || response.sessionArtifactId !== binding.sessionArtifactId
      || response.closed !== true) {
      return fail(
        "autonomous_linux_cleanup_ack_invalid",
        "The fixed cleanup endpoint did not confirm closure of the exact candidate session.",
      );
    }
    return Object.freeze({
      schemaVersion: LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
      sessionArtifactId: binding.sessionArtifactId,
      closed: true,
      observedAt: observedAt(response.observedAt, "Cleanup acknowledgement time"),
      receiptSha256: responseHash(response, "receiptSha256"),
    });
  }
}

/**
 * Production adapter for a separately attested candidate runtime. The
 * transport receives only the fixed typed operations above; unlike the
 * disposable loopback fixture it receives no URL or network-origin authority.
 */
export class BoundedCandidateRuntimeLinuxPrivilegeAdapter
implements CandidateLinuxPrivilegeContinuationAdapterPort {
  constructor(
    private readonly transport: CandidateRuntimeLinuxPrivilegeTransport,
  ) {}

  async requestPrivilegeEscalation(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<LoopbackLinuxPrivilegeAck> {
    assertRuntimeBinding(binding);
    const response = await this.transport.invoke(Object.freeze({
      operation: "privilege_escalation",
      transportBindingId: binding.transportBindingId,
      postExploitSpecId: binding.postExploitSpecId,
      sessionArtifactId: binding.sessionArtifactId,
      exactTarget: binding.exactTarget,
      candidateBindingHash: binding.candidateBindingHash,
      leaseFencingToken: binding.leaseFencingToken,
      actionId,
    }), signal);
    if (!plain(response) || !exactKeys(response, [
      "schemaVersion",
      "sessionArtifactId",
      "accepted",
      "observedAt",
      "receiptSha256",
    ]) || response.schemaVersion !== LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION
      || response.sessionArtifactId !== binding.sessionArtifactId
      || response.accepted !== true) {
      return fail(
        "autonomous_linux_candidate_runtime_privilege_ack_invalid",
        "The reviewed candidate runtime did not return the exact privilege acknowledgement.",
      );
    }
    return Object.freeze({
      schemaVersion: LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
      sessionArtifactId: binding.sessionArtifactId,
      accepted: true,
      observedAt: observedAt(
        response.observedAt,
        "Candidate runtime privilege acknowledgement time",
      ),
      receiptSha256: responseHash(response, "receiptSha256"),
    });
  }

  async observeRootIdentity(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<IndependentRootIdentityObservation> {
    assertRuntimeBinding(binding);
    const response = await this.transport.invoke(Object.freeze({
      operation: "observe_root_identity",
      transportBindingId: binding.transportBindingId,
      postExploitSpecId: binding.postExploitSpecId,
      sessionArtifactId: binding.sessionArtifactId,
      exactTarget: binding.exactTarget,
      candidateBindingHash: binding.candidateBindingHash,
      leaseFencingToken: binding.leaseFencingToken,
      actionId,
    }), signal);
    if (!plain(response) || !exactKeys(response, [
      "schemaVersion",
      "sessionArtifactId",
      "principal",
      "uid",
      "gid",
      "groups",
      "observedAt",
      "observationSha256",
    ]) || response.schemaVersion !== LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION
      || response.sessionArtifactId !== binding.sessionArtifactId
      || response.principal !== "root"
      || response.uid !== 0
      || response.gid !== 0
      || !Array.isArray(response.groups)
      || response.groups.length < 1
      || response.groups.length > 32
      || response.groups.some((group) =>
        typeof group !== "string"
        || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/u.test(group))) {
      return fail(
        "autonomous_linux_candidate_runtime_root_identity_invalid",
        "The independent candidate-runtime observer did not prove root with UID and GID zero.",
      );
    }
    return Object.freeze({
      schemaVersion: LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
      sessionArtifactId: binding.sessionArtifactId,
      principal: "root",
      uid: 0,
      gid: 0,
      groups: Object.freeze([
        ...new Set(response.groups as string[]),
      ]),
      observedAt: observedAt(
        response.observedAt,
        "Candidate runtime root identity observation time",
      ),
      observationSha256: responseHash(response, "observationSha256"),
    });
  }

  async proveRootFlag(
    binding: CandidateLinuxPrivilegeSessionBinding,
    actionId: string,
    signal: AbortSignal,
  ): Promise<RootFlagHashProof> {
    assertRuntimeBinding(binding);
    if (binding.declaredRootFlagPath !== ROOT_FLAG_PATH) {
      return fail(
        "autonomous_linux_candidate_runtime_root_flag_path_invalid",
        "The reviewed candidate runtime accepts exactly /root/root.txt.",
      );
    }
    const response = await this.transport.invoke(Object.freeze({
      operation: "prove_root_flag_hash",
      transportBindingId: binding.transportBindingId,
      postExploitSpecId: binding.postExploitSpecId,
      sessionArtifactId: binding.sessionArtifactId,
      exactTarget: binding.exactTarget,
      candidateBindingHash: binding.candidateBindingHash,
      leaseFencingToken: binding.leaseFencingToken,
      actionId,
      declaredPath: ROOT_FLAG_PATH,
    }), signal);
    if (!plain(response) || !exactKeys(response, [
      "schemaVersion",
      "sessionArtifactId",
      "declaredPath",
      "contentSha256",
      "byteSize",
      "observedAt",
      "proofSha256",
    ]) || response.schemaVersion !== LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION
      || response.sessionArtifactId !== binding.sessionArtifactId
      || response.declaredPath !== ROOT_FLAG_PATH
      || typeof response.contentSha256 !== "string"
      || !SHA256.test(response.contentSha256)
      || !Number.isSafeInteger(response.byteSize)
      || Number(response.byteSize) < 1
      || Number(response.byteSize) > 4_096) {
      return fail(
        "autonomous_linux_candidate_runtime_root_flag_proof_invalid",
        "The candidate runtime did not return one exact hash-only /root/root.txt receipt.",
      );
    }
    return Object.freeze({
      schemaVersion: LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
      sessionArtifactId: binding.sessionArtifactId,
      declaredPath: ROOT_FLAG_PATH,
      contentSha256: response.contentSha256,
      byteSize: Number(response.byteSize),
      observedAt: observedAt(
        response.observedAt,
        "Candidate runtime root flag proof time",
      ),
      proofSha256: responseHash(response, "proofSha256"),
    });
  }

  async cleanup(
    binding: CandidateLinuxPrivilegeSessionBinding,
    reason: string,
    signal: AbortSignal,
  ): Promise<LoopbackLinuxCleanupAck> {
    assertRuntimeBinding(binding);
    const normalizedReason = reason
      .replace(/[\u0000-\u001F\u007F]/gu, " ")
      .trim().replace(/\s+/gu, " ").slice(0, 300);
    if (!normalizedReason) {
      return fail(
        "autonomous_linux_candidate_runtime_cleanup_reason_invalid",
        "A bounded cleanup reason is required.",
      );
    }
    const response = await this.transport.invoke(Object.freeze({
      operation: "cleanup",
      transportBindingId: binding.transportBindingId,
      postExploitSpecId: binding.postExploitSpecId,
      sessionArtifactId: binding.sessionArtifactId,
      exactTarget: binding.exactTarget,
      candidateBindingHash: binding.candidateBindingHash,
      leaseFencingToken: binding.leaseFencingToken,
      reason: normalizedReason,
    }), signal);
    if (!plain(response) || !exactKeys(response, [
      "schemaVersion",
      "sessionArtifactId",
      "closed",
      "observedAt",
      "receiptSha256",
    ]) || response.schemaVersion !== LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION
      || response.sessionArtifactId !== binding.sessionArtifactId
      || response.closed !== true) {
      return fail(
        "autonomous_linux_candidate_runtime_cleanup_ack_invalid",
        "The reviewed candidate runtime did not confirm closure of the exact session.",
      );
    }
    return Object.freeze({
      schemaVersion: LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
      sessionArtifactId: binding.sessionArtifactId,
      closed: true,
      observedAt: observedAt(
        response.observedAt,
        "Candidate runtime cleanup acknowledgement time",
      ),
      receiptSha256: responseHash(response, "receiptSha256"),
    });
  }
}

export const AUTONOMOUS_LINUX_ROOT_FLAG_PATH = ROOT_FLAG_PATH;

import { createHash } from "node:crypto";
import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
  readFileSync,
} from "node:fs";
import { createConnection, createServer, isIP, type Server, type Socket } from "node:net";
import { isAbsolute, resolve, sep } from "node:path";
import type { SqliteDatabase } from "../db";
import { digestCanonicalJson } from "../mcp";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";
import {
  CandidateLinuxPostExploitSpecRegistry,
  type CandidateLinuxPostExploitSpecRecord,
} from "./CandidateLinuxPostExploitSpecRegistry";
import type {
  CandidateLinuxTransportBindingHandler,
} from "./CandidateLinuxTransportBroker";
import {
  CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
  type CandidateLinuxTransportBindingManifest,
  type CandidateLinuxTransportOperation,
  type CandidateLinuxTransportRequest,
} from "./CandidateLinuxTransportBindingRegistry";
import {
  candidateLinuxTargetScopeMatches,
  candidateLinuxTargetScopesEqual,
  parseCandidateLinuxTargetScope,
  type CandidateLinuxTargetScope,
} from "./CandidateLinuxTargetScope";

export const REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION =
  "ti-scale.reviewed-real-candidate-linux-profile.v1" as const;
export const REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION =
  "ti-scale.reviewed-real-candidate-linux-adapter.v1" as const;
export const REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION =
  "ti-scale.reviewed-real-candidate-linux-procedure.v1" as const;
export const REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_ATTESTATION_SCHEMA_VERSION =
  "ti-scale.reviewed-real-candidate-linux-adapter-attestation.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const PRINCIPAL = /^[a-z_][a-z0-9_-]{0,63}$/u;
const USER_FLAG_PATH = /^\/home\/([a-z_][a-z0-9_-]{0,63})\/user\.txt$/u;
const CONTROL = /[\u0000-\u001F\u007F]/u;
const MAXIMUM_MESSAGE_BYTES = 64 * 1_024;
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

export interface ReviewedRealCandidateLinuxProfile {
  readonly schemaVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION;
  readonly profileId: string;
  readonly candidateClass: "reviewed_real_candidate_v1";
  readonly realTargetSupport: true;
  readonly targetScope: CandidateLinuxTargetScope;
  readonly bindingId: string;
  readonly postExploitSpec: Readonly<{
    readonly id: string;
    readonly expectedSha256: string;
    readonly exploitOutcomeObserverSpecId: string;
    readonly scriptArtifactId: string;
    readonly expectedPrincipal: string;
    readonly expectedUid: number;
    readonly declaredUserFlagPath: string;
    readonly declaredRootFlagPath: "/root/root.txt";
  }>;
  readonly adapter: Readonly<{
    readonly executablePath: string;
    readonly executableSha256: string;
    readonly socketPath: string;
    readonly socketGid: number;
    readonly protocolVersion:
      typeof REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION;
  }>;
  /**
   * Candidate-specific closed procedure provider. This is intentionally
   * distinct from the exploit ScriptArtifact: its separately reviewed bytes
   * translate only the eight typed operations below into the candidate's
   * already reviewed session mechanism.
   */
  readonly procedure: Readonly<{
    readonly executablePath: string;
    readonly executableSha256: string;
    readonly protocolVersion:
      typeof REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION;
  }>;
  readonly boundary: Readonly<{
    readonly typedOperationsOnly: true;
    readonly genericCommand: false;
    readonly shell: false;
    readonly argv: false;
    readonly payload: false;
    readonly credentialsFromRuntime: false;
    readonly exactTargetFromCanonicalAction: true;
    readonly succeededAttackAttemptRequired: true;
    readonly derivedCurrentRunSpecOnly: true;
    readonly publicProvider: false;
    readonly hashOnlyFlagProofs: true;
  }>;
  readonly operations: readonly CandidateLinuxTransportOperation[];
}

export interface ReviewedRealCandidateLinuxAdapterAttestation {
  readonly schemaVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_ATTESTATION_SCHEMA_VERSION;
  readonly protocolVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION;
  readonly profileSha256: string;
  readonly adapterExecutableSha256: string;
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly candidateClass: "reviewed_real_candidate_v1";
  readonly realTargetSupport: true;
  readonly targetScope: CandidateLinuxTargetScope;
  readonly operations: readonly CandidateLinuxTransportOperation[];
  readonly boundary: ReviewedRealCandidateLinuxProfile["boundary"];
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly receiptSha256: string;
}

export interface ReviewedRealCandidateLinuxAdapterImplementation {
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly profileSha256: string;
  readonly adapterExecutableSha256: string;
  readonly candidateClass: "reviewed_real_candidate_v1";
  readonly realTargetSupport: true;
  readonly targetScope: CandidateLinuxTargetScope;
  /**
   * Proves that the reviewed implementation boundary is installed and still
   * bound to the profile. An implementation may be either a fixed
   * procedure-specific provider or a conditional run-scoped bridge. A
   * conditional bridge can attest before discovery, but that attestation
   * never grants candidate dispatch: the exact current-run procedure still
   * requires its own immutable activation and provider attestation.
   */
  attest(signal: AbortSignal): Promise<void>;
  handle(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown>;
}

export interface ReviewedRealCandidateLinuxAdapterHandle {
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
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    throw new TypeError(`${label} contains an unreviewed field`);
  }
}

function stableId(value: unknown, label: string): string {
  if (typeof value !== "string" || !ID.test(value)) {
    throw new TypeError(`${label} must be a stable identifier`);
  }
  return value;
}

function sha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256`);
  }
  return value;
}

function absolutePath(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || value !== value.trim()
    || !isAbsolute(value)
    || value === resolve(sep)
    || value.length > 4_096
    || CONTROL.test(value)
  ) {
    throw new TypeError(`${label} must be a safe absolute path`);
  }
  return resolve(value);
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new TypeError(`${label} must be a non-negative integer`);
  }
  return Number(value);
}

function exactBoundary(
  value: unknown,
): ReviewedRealCandidateLinuxProfile["boundary"] {
  const boundary = plain(value, "reviewed real candidate boundary");
  exactKeys(boundary, [
    "argv",
    "credentialsFromRuntime",
    "derivedCurrentRunSpecOnly",
    "exactTargetFromCanonicalAction",
    "genericCommand",
    "hashOnlyFlagProofs",
    "payload",
    "publicProvider",
    "shell",
    "succeededAttackAttemptRequired",
    "typedOperationsOnly",
  ], "reviewed real candidate boundary");
  const expected = {
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
  } as const;
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (boundary[key] !== expectedValue) {
      throw new TypeError(
        `reviewed real candidate boundary.${key} must equal ${String(expectedValue)}`,
      );
    }
  }
  return Object.freeze(expected);
}

function exactOperations(
  value: unknown,
): readonly CandidateLinuxTransportOperation[] {
  if (
    !Array.isArray(value)
    || value.length !== OPERATIONS.length
    || value.some((operation, index) => operation !== OPERATIONS[index])
  ) {
    throw new TypeError(
      "reviewed real candidate operations must be the complete ordered closed set",
    );
  }
  return OPERATIONS;
}

export function parseReviewedRealCandidateLinuxProfile(
  input: unknown,
): ReviewedRealCandidateLinuxProfile {
  const root = plain(input, "reviewed real candidate profile");
  exactKeys(root, [
    "adapter",
    "bindingId",
    "boundary",
    "candidateClass",
    "operations",
    "postExploitSpec",
    "procedure",
    "profileId",
    "realTargetSupport",
    "schemaVersion",
    "targetScope",
  ], "reviewed real candidate profile");
  if (
    root.schemaVersion !== REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION
    || root.candidateClass !== "reviewed_real_candidate_v1"
    || root.realTargetSupport !== true
  ) {
    throw new TypeError(
      "The profile must be an explicit reviewed real-candidate binding",
    );
  }
  const spec = plain(root.postExploitSpec, "postExploitSpec");
  exactKeys(spec, [
    "declaredRootFlagPath",
    "declaredUserFlagPath",
    "expectedPrincipal",
    "expectedSha256",
    "expectedUid",
    "exploitOutcomeObserverSpecId",
    "id",
    "scriptArtifactId",
  ], "postExploitSpec");
  if (
    typeof spec.expectedPrincipal !== "string"
    || !PRINCIPAL.test(spec.expectedPrincipal)
    || !Number.isSafeInteger(spec.expectedUid)
    || Number(spec.expectedUid) < 1
    || typeof spec.declaredUserFlagPath !== "string"
    || !USER_FLAG_PATH.test(spec.declaredUserFlagPath)
    || USER_FLAG_PATH.exec(spec.declaredUserFlagPath)?.[1]
      !== spec.expectedPrincipal
    || spec.declaredRootFlagPath !== "/root/root.txt"
  ) {
    throw new TypeError(
      "The reviewed real-candidate identity and proof paths are invalid",
    );
  }
  const adapter = plain(root.adapter, "adapter");
  exactKeys(adapter, [
    "executablePath",
    "executableSha256",
    "protocolVersion",
    "socketGid",
    "socketPath",
  ], "adapter");
  if (
    adapter.protocolVersion
      !== REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION
  ) {
    throw new TypeError("The reviewed real-candidate adapter protocol is invalid");
  }
  const procedure = plain(root.procedure, "procedure");
  exactKeys(procedure, [
    "executablePath",
    "executableSha256",
    "protocolVersion",
  ], "procedure");
  if (
    procedure.protocolVersion
      !== REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION
  ) {
    throw new TypeError(
      "The reviewed real-candidate procedure protocol is invalid",
    );
  }
  return Object.freeze({
    schemaVersion: REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
    profileId: stableId(root.profileId, "profileId"),
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: parseCandidateLinuxTargetScope(root.targetScope),
    bindingId: stableId(root.bindingId, "bindingId"),
    postExploitSpec: Object.freeze({
      id: stableId(spec.id, "postExploitSpec.id"),
      expectedSha256: sha256(
        spec.expectedSha256,
        "postExploitSpec.expectedSha256",
      ),
      exploitOutcomeObserverSpecId: stableId(
        spec.exploitOutcomeObserverSpecId,
        "postExploitSpec.exploitOutcomeObserverSpecId",
      ),
      scriptArtifactId: stableId(
        spec.scriptArtifactId,
        "postExploitSpec.scriptArtifactId",
      ),
      expectedPrincipal: spec.expectedPrincipal,
      expectedUid: Number(spec.expectedUid),
      declaredUserFlagPath: spec.declaredUserFlagPath,
      declaredRootFlagPath: "/root/root.txt",
    }),
    adapter: Object.freeze({
      executablePath: absolutePath(
        adapter.executablePath,
        "adapter.executablePath",
      ),
      executableSha256: sha256(
        adapter.executableSha256,
        "adapter.executableSha256",
      ),
      socketPath: absolutePath(adapter.socketPath, "adapter.socketPath"),
      socketGid: nonNegativeInteger(adapter.socketGid, "adapter.socketGid"),
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
    }),
    procedure: Object.freeze({
      executablePath: absolutePath(
        procedure.executablePath,
        "procedure.executablePath",
      ),
      executableSha256: sha256(
        procedure.executableSha256,
        "procedure.executableSha256",
      ),
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
    }),
    boundary: exactBoundary(root.boundary),
    operations: exactOperations(root.operations),
  });
}

export function loadTrustedReviewedRealCandidateLinuxProfile(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<ReviewedRealCandidateLinuxProfile> {
  return loadTrustedJson(
    { ...reference, maximumBytes: reference.maximumBytes ?? 64 * 1_024 },
    parseReviewedRealCandidateLinuxProfile,
  );
}

function hashFile(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function assertPinnedExecutable(path: string, expectedSha256: string): void {
  const metadata = lstatSync(path);
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || ![0, currentUid].includes(metadata.uid)
    || (metadata.mode & 0o022) !== 0
    || hashFile(path) !== expectedSha256
  ) {
    throw new Error(
      "The reviewed real-candidate adapter is not owner-controlled and hash-pinned",
    );
  }
}

function assertSocket(path: string, gid: number): void {
  const metadata = lstatSync(path);
  if (
    !metadata.isSocket()
    || metadata.isSymbolicLink()
    || metadata.gid !== gid
    || (metadata.mode & 0o007) !== 0
  ) {
    throw new Error(
      "The reviewed real-candidate adapter socket ownership is invalid",
    );
  }
}

function safeError(error: unknown): Readonly<{
  readonly code: string;
  readonly message: string;
}> {
  const message = error instanceof Error
    ? error.message
    : "The reviewed real-candidate adapter rejected the request";
  return Object.freeze({
    code: "reviewed_real_candidate_request_rejected",
    message: message.replace(/[\u0000-\u001F\u007F]/gu, " ")
      .replace(/\s+/gu, " ").trim().slice(0, 500),
  });
}

async function unixRequest(
  path: string,
  gid: number,
  request: Readonly<Record<string, unknown>>,
  signal: AbortSignal,
): Promise<unknown> {
  assertSocket(path, gid);
  return await new Promise((resolvePromise, reject) => {
    let socket: Socket | undefined;
    let settled = false;
    let response = "";
    const finish = (error?: Error, value?: unknown) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", abort);
      socket?.destroy();
      error ? reject(error) : resolvePromise(value);
    };
    const abort = () =>
      finish(new Error("Reviewed real-candidate request cancelled"));
    if (signal.aborted) return abort();
    signal.addEventListener("abort", abort, { once: true });
    socket = createConnection({ path });
    socket.setTimeout(5_000);
    socket.on("connect", () => {
      socket?.write(`${JSON.stringify(request)}\n`);
    });
    socket.on("data", (chunk) => {
      response += chunk.toString("utf8");
      if (Buffer.byteLength(response, "utf8") > MAXIMUM_MESSAGE_BYTES) {
        return finish(
          new Error("Reviewed real-candidate response exceeded its bound"),
        );
      }
      const newline = response.indexOf("\n");
      if (newline < 0) return;
      try {
        const envelope = plain(
          JSON.parse(response.slice(0, newline)) as unknown,
          "reviewed real-candidate response",
        );
        exactKeys(
          envelope,
          envelope.ok === true ? ["ok", "result"] : ["error", "ok"],
          "reviewed real-candidate response",
        );
        if (envelope.ok !== true) {
          const failure = plain(
            envelope.error,
            "reviewed real-candidate error",
          );
          throw new Error(
            typeof failure.message === "string"
              ? failure.message
              : "The reviewed real-candidate adapter rejected the request",
          );
        }
        finish(undefined, envelope.result);
      } catch (error) {
        finish(error instanceof Error ? error : new Error(String(error)));
      }
    });
    socket.on("timeout", () =>
      finish(new Error("Reviewed real-candidate adapter timed out")));
    socket.on("error", (error) => finish(error));
    socket.on("end", () => {
      if (!settled) {
        finish(
          new Error(
            "Reviewed real-candidate adapter closed without a response",
          ),
        );
      }
    });
  });
}

function assertProfileBinding(
  loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>,
  binding: CandidateLinuxTransportBindingManifest["bindings"][number],
): void {
  const profile = loadedProfile.value;
  if (
    loadedProfile.receipt.sourceSha256 !== binding.handlerProfileSha256
    || resolve(loadedProfile.receipt.sourcePath) !== binding.handlerProfilePath
    || profile.bindingId !== binding.bindingId
    || profile.postExploitSpec.id !== binding.postExploitSpecId
    || profile.postExploitSpec.expectedSha256
      !== binding.postExploitSpecSha256
    || profile.candidateClass !== binding.candidateClass
    || profile.realTargetSupport !== binding.realTargetSupport
    || !candidateLinuxTargetScopesEqual(
      profile.targetScope,
      binding.targetScope,
    )
    || binding.operations.some(
      (operation, index) => operation !== profile.operations[index],
    )
  ) {
    throw new Error(
      "The reviewed real-candidate profile does not match its pinned transport binding",
    );
  }
}

function adapterAttestation(
  rawValue: unknown,
  loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>,
  now: Date,
): ReviewedRealCandidateLinuxAdapterAttestation {
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
    "targetScope",
  ], "reviewed real-candidate adapter attestation");
  const profile = loadedProfile.value;
  const observedAt = String(raw.observedAt);
  const expiresAt = String(raw.expiresAt);
  const observed = Date.parse(observedAt);
  const expires = Date.parse(expiresAt);
  const operations = exactOperations(raw.operations);
  const boundary = exactBoundary(raw.boundary);
  const unsigned = {
    schemaVersion: raw.schemaVersion,
    protocolVersion: raw.protocolVersion,
    profileSha256: raw.profileSha256,
    adapterExecutableSha256: raw.adapterExecutableSha256,
    bindingId: raw.bindingId,
    postExploitSpecId: raw.postExploitSpecId,
    candidateClass: raw.candidateClass,
    realTargetSupport: raw.realTargetSupport,
    targetScope: raw.targetScope,
    operations: raw.operations,
    boundary: raw.boundary,
    observedAt,
    expiresAt,
  };
  if (
    raw.schemaVersion
      !== REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_ATTESTATION_SCHEMA_VERSION
    || raw.protocolVersion
      !== REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION
    || raw.profileSha256 !== loadedProfile.receipt.sourceSha256
    || raw.adapterExecutableSha256 !== profile.adapter.executableSha256
    || raw.bindingId !== profile.bindingId
    || raw.postExploitSpecId !== profile.postExploitSpec.id
    || raw.candidateClass !== "reviewed_real_candidate_v1"
    || raw.realTargetSupport !== true
    || !candidateLinuxTargetScopesEqual(
      parseCandidateLinuxTargetScope(raw.targetScope),
      profile.targetScope,
    )
    || JSON.stringify(boundary) !== JSON.stringify(profile.boundary)
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
      { maxBytes: 64 * 1_024, maxDepth: 16 },
    ).sha256 !== raw.receiptSha256
  ) {
    throw new Error(
      "The reviewed real-candidate adapter attestation is invalid",
    );
  }
  return Object.freeze({
    ...unsigned,
    schemaVersion:
      REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_ATTESTATION_SCHEMA_VERSION,
    protocolVersion:
      REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
    profileSha256: loadedProfile.receipt.sourceSha256,
    adapterExecutableSha256: profile.adapter.executableSha256,
    bindingId: profile.bindingId,
    postExploitSpecId: profile.postExploitSpec.id,
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: profile.targetScope,
    operations,
    boundary,
    receiptSha256: raw.receiptSha256,
  });
}

/**
 * Broker-side handler for a separately installed, candidate-specific adapter.
 *
 * The adapter is selected by a root-owned hash-pinned profile and speaks only
 * the eight typed operations. The exact IP is copied from the canonical action
 * after the database authorizer verifies mission scope and a succeeded exploit
 * attempt. No command, argv, payload, credential, path override, or provider
 * content can cross this boundary.
 */
export class ReviewedRealCandidateLinuxTransportHandler
implements CandidateLinuxTransportBindingHandler {
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly candidateClass = "reviewed_real_candidate_v1" as const;
  readonly handlerProfileSha256: string;
  readonly realTargetSupport = true as const;
  readonly targetScope: CandidateLinuxTargetScope;
  private currentAttestation?: ReviewedRealCandidateLinuxAdapterAttestation;

  constructor(private readonly options: Readonly<{
    loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>;
    binding: CandidateLinuxTransportBindingManifest["bindings"][number];
    now?: () => Date;
  }>) {
    assertProfileBinding(options.loadedProfile, options.binding);
    assertPinnedExecutable(
      options.loadedProfile.value.adapter.executablePath,
      options.loadedProfile.value.adapter.executableSha256,
    );
    this.bindingId = options.loadedProfile.value.bindingId;
    this.postExploitSpecId = options.loadedProfile.value.postExploitSpec.id;
    this.handlerProfileSha256 =
      options.loadedProfile.receipt.sourceSha256;
    this.targetScope = options.loadedProfile.value.targetScope;
  }

  acceptsPostExploitSpecId(postExploitSpecId: string): boolean {
    // The profile-pinned source is a review template, not executable
    // current-run authority. The database authorizer independently proves
    // that any other stable ID is its byte-identical, current-run clone.
    return ID.test(postExploitSpecId)
      && postExploitSpecId !== this.postExploitSpecId;
  }

  async attest(
    signal: AbortSignal = new AbortController().signal,
  ): Promise<ReviewedRealCandidateLinuxAdapterAttestation> {
    const profile = this.options.loadedProfile.value;
    assertPinnedExecutable(
      profile.adapter.executablePath,
      profile.adapter.executableSha256,
    );
    const raw = await unixRequest(
      profile.adapter.socketPath,
      profile.adapter.socketGid,
      Object.freeze({
        operation: "attest",
        protocolVersion:
          REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
        profileSha256: this.options.loadedProfile.receipt.sourceSha256,
      }),
      signal,
    );
    this.currentAttestation = adapterAttestation(
      raw,
      this.options.loadedProfile,
      (this.options.now ?? (() => new Date()))(),
    );
    return this.currentAttestation;
  }

  async handle(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown> {
    const profile = this.options.loadedProfile.value;
    if (
      request.transportBindingId !== profile.bindingId
      || !this.acceptsPostExploitSpecId(request.postExploitSpecId)
      || isIP(request.exactTarget) === 0
      || !candidateLinuxTargetScopeMatches(
        profile.targetScope,
        request.exactTarget,
      )
      || !profile.operations.includes(request.operation)
    ) {
      throw new Error(
        "The request does not match the reviewed real-candidate profile",
      );
    }
    const now = (this.options.now ?? (() => new Date()))();
    if (
      !this.currentAttestation
      || Date.parse(this.currentAttestation.expiresAt) <= now.getTime()
    ) {
      await this.attest(signal);
    }
    return await unixRequest(
      profile.adapter.socketPath,
      profile.adapter.socketGid,
      Object.freeze({
        operation: "invoke",
        protocolVersion:
          REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
        profileSha256: this.options.loadedProfile.receipt.sourceSha256,
        request,
      }),
      signal,
    );
  }
}

function exactAdapterRequest(
  value: unknown,
  profile: ReviewedRealCandidateLinuxProfile,
): CandidateLinuxTransportRequest {
  const request = plain(value, "reviewed real-candidate adapter request");
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
    exactKeys(request, common, "reviewed real-candidate session request");
  } else if (operation === "prove_user_flag_hash") {
    exactKeys(
      request,
      [...common, "declaredPath"],
      "reviewed real-candidate user-proof request",
    );
    if (request.declaredPath !== profile.postExploitSpec.declaredUserFlagPath) {
      throw new Error("The user-proof path differs from the pinned profile");
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
    ], "reviewed real-candidate privilege request");
  } else if (operation === "prove_root_flag_hash") {
    exactKeys(request, [
      ...common,
      "actionId",
      "candidateBindingHash",
      "declaredPath",
      "leaseFencingToken",
    ], "reviewed real-candidate root-proof request");
    if (request.declaredPath !== "/root/root.txt") {
      throw new Error("The root-proof path differs from /root/root.txt");
    }
  } else if (operation === "cleanup") {
    exactKeys(request, [
      ...common,
      "candidateBindingHash",
      "leaseFencingToken",
      "reason",
    ], "reviewed real-candidate cleanup request");
    if (
      typeof request.reason !== "string"
      || request.reason !== request.reason.trim()
      || request.reason.length < 1
      || request.reason.length > 300
      || CONTROL.test(request.reason)
    ) {
      throw new Error("The cleanup reason is invalid");
    }
  } else {
    throw new Error("The adapter operation is outside the closed set");
  }
  if (
    request.transportBindingId !== profile.bindingId
    || !ID.test(String(request.postExploitSpecId))
    || request.postExploitSpecId === profile.postExploitSpec.id
    || typeof request.sessionArtifactId !== "string"
    || !ID.test(request.sessionArtifactId)
    || typeof request.exactTarget !== "string"
    || isIP(request.exactTarget) === 0
    || !candidateLinuxTargetScopeMatches(
      profile.targetScope,
      request.exactTarget,
    )
  ) {
    throw new Error(
      "The adapter request does not match the profile and canonical IP boundary",
    );
  }
  if ("candidateBindingHash" in request) {
    sha256(request.candidateBindingHash, "candidateBindingHash");
    if (
      !Number.isSafeInteger(request.leaseFencingToken)
      || Number(request.leaseFencingToken) < 1
    ) {
      throw new Error("The adapter request lease fence is invalid");
    }
  }
  if ("actionId" in request) stableId(request.actionId, "actionId");
  return Object.freeze({ ...request }) as CandidateLinuxTransportRequest;
}

/**
 * Hosts one compiled candidate-specific implementation behind the same closed
 * protocol. A deployment must hash-pin the executable that composes this host
 * with its concrete implementation; there is no dynamic module loader.
 */
export async function startReviewedRealCandidateLinuxAdapter(
  input: Readonly<{
    loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>;
    implementation: ReviewedRealCandidateLinuxAdapterImplementation;
    now?: () => Date;
    attestationTtlMs?: number;
  }>,
): Promise<ReviewedRealCandidateLinuxAdapterHandle> {
  const profile = input.loadedProfile.value;
  const implementation = input.implementation;
  const ttl = input.attestationTtlMs ?? 60_000;
  if (
    implementation.bindingId !== profile.bindingId
    || implementation.postExploitSpecId !== profile.postExploitSpec.id
    || implementation.profileSha256
      !== input.loadedProfile.receipt.sourceSha256
    || implementation.adapterExecutableSha256
      !== profile.adapter.executableSha256
    || implementation.candidateClass !== "reviewed_real_candidate_v1"
    || implementation.realTargetSupport !== true
    || !candidateLinuxTargetScopesEqual(
      implementation.targetScope,
      profile.targetScope,
    )
    || !Number.isSafeInteger(ttl)
    || ttl < 1_000
    || ttl > 5 * 60_000
  ) {
    throw new Error(
      "The reviewed real-candidate implementation does not match its pinned profile",
    );
  }
  assertPinnedExecutable(
    profile.adapter.executablePath,
    profile.adapter.executableSha256,
  );
  if (existsSync(profile.adapter.socketPath)) {
    throw new Error(
      "The reviewed real-candidate adapter socket already exists",
    );
  }
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.setTimeout(5_000);
    const controller = new AbortController();
    let body = "";
    let handled = false;
    const cancel = () =>
      controller.abort(new Error("Reviewed real-candidate client disconnected"));
    socket.once("close", cancel);
    socket.once("error", cancel);
    socket.once("timeout", () =>
      socket.destroy(new Error("Reviewed real-candidate request timed out")));
    socket.on("data", (chunk) => {
      if (handled) return;
      body += chunk.toString("utf8");
      if (Buffer.byteLength(body, "utf8") > MAXIMUM_MESSAGE_BYTES) {
        handled = true;
        socket.end(`${JSON.stringify({
          ok: false,
          error: safeError(
            new Error("Reviewed real-candidate request exceeded its bound"),
          ),
        })}\n`);
        return;
      }
      const newline = body.indexOf("\n");
      if (newline < 0) return;
      handled = true;
      void (async () => {
        try {
          const envelope = plain(
            JSON.parse(body.slice(0, newline)) as unknown,
            "reviewed real-candidate envelope",
          );
          if (envelope.operation === "attest") {
            exactKeys(
              envelope,
              ["operation", "profileSha256", "protocolVersion"],
              "reviewed real-candidate attestation envelope",
            );
            if (
              envelope.profileSha256
                !== input.loadedProfile.receipt.sourceSha256
              || envelope.protocolVersion
                !== REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION
            ) {
              throw new Error(
                "The reviewed real-candidate attestation identity is invalid",
              );
            }
            await implementation.attest(controller.signal);
            const observedAt = (input.now ?? (() => new Date()))();
            const unsigned = {
              schemaVersion:
                REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_ATTESTATION_SCHEMA_VERSION,
              protocolVersion:
                REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
              profileSha256: input.loadedProfile.receipt.sourceSha256,
              adapterExecutableSha256: profile.adapter.executableSha256,
              bindingId: profile.bindingId,
              postExploitSpecId: profile.postExploitSpec.id,
              candidateClass: "reviewed_real_candidate_v1" as const,
              realTargetSupport: true as const,
              targetScope: profile.targetScope,
              operations: profile.operations,
              boundary: profile.boundary,
              observedAt: observedAt.toISOString(),
              expiresAt: new Date(
                observedAt.getTime() + ttl,
              ).toISOString(),
            };
            socket.end(`${JSON.stringify({
              ok: true,
              result: {
                ...unsigned,
                receiptSha256: digestCanonicalJson(
                  unsigned,
                  { maxBytes: 64 * 1_024, maxDepth: 16 },
                ).sha256,
              },
            })}\n`);
            return;
          }
          exactKeys(
            envelope,
            ["operation", "profileSha256", "protocolVersion", "request"],
            "reviewed real-candidate invocation envelope",
          );
          if (
            envelope.operation !== "invoke"
            || envelope.profileSha256
              !== input.loadedProfile.receipt.sourceSha256
            || envelope.protocolVersion
              !== REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION
          ) {
            throw new Error(
              "The reviewed real-candidate invocation identity is invalid",
            );
          }
          const request = exactAdapterRequest(envelope.request, profile);
          const result = await implementation.handle(
            request,
            controller.signal,
          );
          socket.end(`${JSON.stringify({ ok: true, result })}\n`);
        } catch (error) {
          socket.end(`${JSON.stringify({
            ok: false,
            error: safeError(error),
          })}\n`);
        }
      })();
    });
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(profile.adapter.socketPath, () => {
      server.off("error", reject);
      resolvePromise();
    });
  });
  chmodSync(profile.adapter.socketPath, 0o660);
  chownSync(profile.adapter.socketPath, -1, profile.adapter.socketGid);
  assertSocket(profile.adapter.socketPath, profile.adapter.socketGid);
  return Object.freeze({
    socketPath: profile.adapter.socketPath,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolvePromise, reject) => {
        server.close((error) =>
          error ? reject(error) : resolvePromise());
      });
    },
  });
}

/**
 * Registers the exact source ScriptArtifact/observer/spec identity pinned by
 * one reviewed real-candidate profile. It creates no session and grants no
 * execution authority; lifecycle readiness still requires the separate live
 * broker and adapter attestations.
 */
export function registerReviewedRealCandidateLinuxPostExploitSpec(
  input: Readonly<{
    database: SqliteDatabase;
    loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>;
    binding: CandidateLinuxTransportBindingManifest["bindings"][number];
    createdBy: string;
    now?: () => Date;
  }>,
): CandidateLinuxPostExploitSpecRecord {
  assertProfileBinding(input.loadedProfile, input.binding);
  const profile = input.loadedProfile.value;
  const created = new CandidateLinuxPostExploitSpecRegistry(
    input.database,
    input.now,
  ).register({
    id: profile.postExploitSpec.id,
    exploitOutcomeObserverSpecId:
      profile.postExploitSpec.exploitOutcomeObserverSpecId,
    scriptArtifactId: profile.postExploitSpec.scriptArtifactId,
    transportType: "candidate_runtime_session_v1",
    transportBindingId: profile.bindingId,
    expectedPrincipal: profile.postExploitSpec.expectedPrincipal,
    expectedUid: profile.postExploitSpec.expectedUid,
    declaredUserFlagPath:
      profile.postExploitSpec.declaredUserFlagPath,
    createdBy: input.createdBy,
  });
  if (
    created.id !== profile.postExploitSpec.id
    || created.specHash !== profile.postExploitSpec.expectedSha256
    || created.transportBindingId !== profile.bindingId
    || created.transportType !== "candidate_runtime_session_v1"
  ) {
    throw new Error(
      "The registered real-candidate post-exploit specification does not match its pinned profile",
    );
  }
  return created;
}

export function reviewedRealCandidateLinuxOperations():
readonly CandidateLinuxTransportOperation[] {
  return OPERATIONS;
}

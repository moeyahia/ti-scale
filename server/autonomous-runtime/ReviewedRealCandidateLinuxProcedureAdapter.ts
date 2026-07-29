import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { isIP } from "node:net";
import { isAbsolute, resolve, sep } from "node:path";
import { digestCanonicalJson } from "../mcp";
import {
  LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
} from "./CandidateLinuxPrivilegeContinuation";
import type {
  CandidateLinuxTransportOperation,
  CandidateLinuxTransportRequest,
} from "./CandidateLinuxTransportBindingRegistry";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
  type ReviewedRealCandidateLinuxAdapterImplementation,
  type ReviewedRealCandidateLinuxProfile,
} from "./ReviewedRealCandidateLinuxTransport";
import {
  candidateLinuxTargetScopeMatches,
  candidateLinuxTargetScopesEqual,
  parseCandidateLinuxTargetScope,
  type CandidateLinuxTargetScope,
} from "./CandidateLinuxTargetScope";

export const REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_ATTESTATION_SCHEMA_VERSION =
  "ti-scale.reviewed-real-candidate-linux-procedure-attestation.v1" as const;
export const REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_CONFORMANCE_SCHEMA_VERSION =
  "ti-scale.reviewed-real-candidate-linux-procedure-conformance.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const PRINCIPAL = /^[a-z_][a-z0-9_-]{0,63}$/u;
const CONTROL = /[\u0000-\u001F\u007F]/u;
const MAXIMUM_RESPONSE_BYTES = 64 * 1_024;
const MINIMUM_TIMEOUT_MS = 100;
const MAXIMUM_TIMEOUT_MS = 30_000;
const OPERATIONS = Object.freeze([
  "open",
  "observe_identity",
  "prove_user_flag_hash",
  "close",
  "privilege_escalation",
  "observe_root_identity",
  "prove_root_flag_hash",
  "cleanup",
] as const satisfies readonly CandidateLinuxTransportOperation[]);
const BOUNDARY = Object.freeze({
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

export interface ReviewedRealCandidateLinuxProcedureAttestation {
  readonly schemaVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_ATTESTATION_SCHEMA_VERSION;
  readonly protocolVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION;
  readonly profileSha256: string;
  readonly procedureExecutableSha256: string;
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly scriptArtifactId: string;
  readonly exploitOutcomeObserverSpecId: string;
  readonly candidateClass: "reviewed_real_candidate_v1";
  readonly realTargetSupport: true;
  readonly targetScope: CandidateLinuxTargetScope;
  readonly operations: readonly CandidateLinuxTransportOperation[];
  readonly boundary: typeof BOUNDARY;
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly receiptSha256: string;
}

export interface ReviewedRealCandidateLinuxProcedureConformance {
  readonly schemaVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_CONFORMANCE_SCHEMA_VERSION;
  readonly protocolVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION;
  readonly profileSha256: string;
  readonly procedureExecutableSha256: string;
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly scriptArtifactId: string;
  readonly exploitOutcomeObserverSpecId: string;
  readonly targetScope: CandidateLinuxTargetScope;
  readonly cases: readonly Readonly<{
    readonly operation: CandidateLinuxTransportOperation;
    readonly result: Readonly<Record<string, unknown>>;
  }>[];
  readonly receiptSha256: string;
}

/**
 * Narrow candidate-specific provider seam.
 *
 * A provider receives only the closed request union already authorized by the
 * database-backed broker. It cannot receive a command, shell, argv, payload,
 * credential, arbitrary proof path, or target selected outside the canonical
 * action. A particular engagement still needs a separately reviewed provider
 * executable which implements these operations for its exact exploit/session
 * mechanism.
 */
export interface ReviewedRealCandidateLinuxProcedureProvider {
  readonly profileSha256: string;
  readonly procedureExecutableSha256: string;
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly scriptArtifactId: string;
  readonly exploitOutcomeObserverSpecId: string;
  readonly candidateClass: "reviewed_real_candidate_v1";
  readonly realTargetSupport: true;
  readonly targetScope: CandidateLinuxTargetScope;
  attest(signal: AbortSignal): Promise<ReviewedRealCandidateLinuxProcedureAttestation>;
  conform(
    signal: AbortSignal,
  ): Promise<ReviewedRealCandidateLinuxProcedureConformance>;
  invoke(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown>;
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

function stableId(value: unknown, label: string): string {
  if (typeof value !== "string" || !ID.test(value)) {
    throw new TypeError(`${label} must be a stable identifier`);
  }
  return value;
}

function hash(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256`);
  }
  return value;
}

function absolutePath(value: string, label: string): string {
  if (
    value !== value.trim()
    || !isAbsolute(value)
    || value === resolve(sep)
    || value.length > 4_096
    || CONTROL.test(value)
  ) {
    throw new TypeError(`${label} must be a safe absolute path`);
  }
  return resolve(value);
}

function hashFile(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function assertPinnedExecutable(
  path: string,
  expectedSha256: string,
  allowedOwnerUids: readonly number[],
): void {
  const metadata = lstatSync(path);
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || !allowedOwnerUids.includes(metadata.uid)
    || (metadata.mode & 0o022) !== 0
    || (metadata.mode & 0o111) === 0
    || metadata.size < 1
    || metadata.size > 32 * 1_024 * 1_024
    || hashFile(path) !== expectedSha256
  ) {
    throw new Error(
      "The reviewed candidate procedure executable is not owner-controlled and hash-pinned",
    );
  }
}

function terminate(child: ChildProcess, signal: NodeJS.Signals): void {
  if (!child.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch {
    try {
      child.kill(signal);
    } catch {
      // The process already reached a terminal state.
    }
  }
}

async function runPinnedProcedure(input: Readonly<{
  executablePath: string;
  executableSha256: string;
  allowedOwnerUids: readonly number[];
  envelope: Readonly<Record<string, unknown>>;
  timeoutMs: number;
  signal: AbortSignal;
}>): Promise<unknown> {
  if (input.signal.aborted) {
    throw new Error("Reviewed candidate procedure request cancelled");
  }
  assertPinnedExecutable(
    input.executablePath,
    input.executableSha256,
    input.allowedOwnerUids,
  );
  const descriptor = openSync(
    input.executablePath,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  const opened = fstatSync(descriptor);
  if (
    !opened.isFile()
    || !input.allowedOwnerUids.includes(opened.uid)
    || (opened.mode & 0o022) !== 0
    || (opened.mode & 0o111) === 0
    || opened.size < 1
    || opened.size > 32 * 1_024 * 1_024
  ) {
    closeSync(descriptor);
    throw new Error("The reviewed candidate procedure identity changed");
  }
  try {
    const executableBytes = readFileSync(descriptor);
    const afterRead = fstatSync(descriptor);
    if (
      opened.dev !== afterRead.dev
      || opened.ino !== afterRead.ino
      || opened.size !== afterRead.size
      || opened.mtimeMs !== afterRead.mtimeMs
      || executableBytes.byteLength < 1
      || executableBytes.byteLength > 32 * 1_024 * 1_024
      || createHash("sha256").update(executableBytes).digest("hex")
        !== input.executableSha256
    ) {
      throw new Error("The reviewed candidate procedure identity changed");
    }
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
  let child: ChildProcess;
  try {
    child = spawn("/proc/self/fd/3", [], {
      cwd: "/",
      env: Object.freeze({
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      }),
      shell: false,
      detached: true,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe", descriptor],
    });
  } finally {
    closeSync(descriptor);
  }
  let stdout = "";
  let stderr = "";
  let outputBytes = 0;
  let terminal = false;
  let forcedKill: ReturnType<typeof setTimeout> | undefined;
  const stop = (reason: "cancelled" | "timed_out" | "output_limit") => {
    if (terminal) return;
    terminal = true;
    terminate(child, "SIGTERM");
    forcedKill = setTimeout(() => terminate(child, "SIGKILL"), 250);
    forcedKill.unref?.();
    return reason;
  };
  const abort = () => stop("cancelled");
  input.signal.addEventListener("abort", abort, { once: true });
  const timeout = setTimeout(() => stop("timed_out"), input.timeoutMs);
  timeout.unref?.();
  const append = (stream: "stdout" | "stderr", chunk: Buffer | string) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    outputBytes += bytes.byteLength;
    if (outputBytes > MAXIMUM_RESPONSE_BYTES) {
      stop("output_limit");
      return;
    }
    if (stream === "stdout") stdout += bytes.toString("utf8");
    else stderr += bytes.toString("utf8");
  };
  child.stdout?.on("data", (chunk) => append("stdout", chunk as Buffer));
  child.stderr?.on("data", (chunk) => append("stderr", chunk as Buffer));
  child.stdin?.end(`${JSON.stringify(input.envelope)}\n`);
  const completion = await new Promise<Readonly<{
    exitCode: number | null;
    signal: NodeJS.Signals | null;
  }>>((resolvePromise) => {
    let settled = false;
    child.once("error", () => {
      if (settled) return;
      settled = true;
      resolvePromise({ exitCode: null, signal: null });
    });
    child.once("close", (exitCode, closeSignal) => {
      if (settled) return;
      settled = true;
      resolvePromise({ exitCode, signal: closeSignal });
    });
  });
  clearTimeout(timeout);
  if (forcedKill) clearTimeout(forcedKill);
  input.signal.removeEventListener("abort", abort);
  if (input.signal.aborted) {
    throw new Error("Reviewed candidate procedure request cancelled");
  }
  if (completion.exitCode !== 0 || completion.signal || terminal) {
    throw new Error(
      `Reviewed candidate procedure failed: ${stderr.replace(/[\u0000-\u001F\u007F]/gu, " ").replace(/\s+/gu, " ").trim().slice(0, 300) || "bounded process failure"}`,
    );
  }
  const lines = stdout.trim().split(/\r?\n/u);
  if (lines.length !== 1 || !lines[0]) {
    throw new Error(
      "Reviewed candidate procedure must return exactly one JSON envelope",
    );
  }
  const response = plain(
    JSON.parse(lines[0]) as unknown,
    "reviewed candidate procedure response",
  );
  exactKeys(
    response,
    response.ok === true ? ["ok", "result"] : ["error", "ok"],
    "reviewed candidate procedure response",
  );
  if (response.ok !== true) {
    const error = plain(response.error, "reviewed candidate procedure error");
    exactKeys(error, ["code", "message"], "reviewed candidate procedure error");
    throw new Error(
      typeof error.message === "string"
        ? error.message.replace(/[\u0000-\u001F\u007F]/gu, " ")
          .replace(/\s+/gu, " ").trim().slice(0, 500)
        : "Reviewed candidate procedure rejected the request",
    );
  }
  return response.result;
}

function exactBoundary(value: unknown): typeof BOUNDARY {
  const boundary = plain(value, "reviewed candidate procedure boundary");
  exactKeys(
    boundary,
    Object.keys(BOUNDARY),
    "reviewed candidate procedure boundary",
  );
  for (const [key, expected] of Object.entries(BOUNDARY)) {
    if (boundary[key] !== expected) {
      throw new TypeError(
        `reviewed candidate procedure boundary.${key} must equal ${String(expected)}`,
      );
    }
  }
  return BOUNDARY;
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
      "Reviewed candidate procedure operations must be the complete ordered closed set",
    );
  }
  return OPERATIONS;
}

function parseAttestation(
  value: unknown,
  expected: Readonly<{
    profileSha256: string;
    procedureExecutableSha256: string;
    bindingId: string;
    postExploitSpecId: string;
    scriptArtifactId: string;
    exploitOutcomeObserverSpecId: string;
    targetScope: CandidateLinuxTargetScope;
    now: Date;
  }>,
): ReviewedRealCandidateLinuxProcedureAttestation {
  const attestation = plain(
    value,
    "reviewed candidate procedure attestation",
  );
  exactKeys(attestation, [
    "bindingId",
    "boundary",
    "candidateClass",
    "expiresAt",
    "exploitOutcomeObserverSpecId",
    "observedAt",
    "operations",
    "postExploitSpecId",
    "procedureExecutableSha256",
    "profileSha256",
    "protocolVersion",
    "realTargetSupport",
    "receiptSha256",
    "schemaVersion",
    "scriptArtifactId",
    "targetScope",
  ], "reviewed candidate procedure attestation");
  const observed = Date.parse(String(attestation.observedAt));
  const expires = Date.parse(String(attestation.expiresAt));
  const operations = exactOperations(attestation.operations);
  const boundary = exactBoundary(attestation.boundary);
  const unsigned = {
    schemaVersion: attestation.schemaVersion,
    protocolVersion: attestation.protocolVersion,
    profileSha256: attestation.profileSha256,
    procedureExecutableSha256: attestation.procedureExecutableSha256,
    bindingId: attestation.bindingId,
    postExploitSpecId: attestation.postExploitSpecId,
    scriptArtifactId: attestation.scriptArtifactId,
    exploitOutcomeObserverSpecId:
      attestation.exploitOutcomeObserverSpecId,
    candidateClass: attestation.candidateClass,
    realTargetSupport: attestation.realTargetSupport,
    targetScope: attestation.targetScope,
    operations: attestation.operations,
    boundary: attestation.boundary,
    observedAt: attestation.observedAt,
    expiresAt: attestation.expiresAt,
  };
  if (
    attestation.schemaVersion
      !== REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_ATTESTATION_SCHEMA_VERSION
    || attestation.protocolVersion
      !== REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION
    || attestation.profileSha256 !== expected.profileSha256
    || attestation.procedureExecutableSha256
      !== expected.procedureExecutableSha256
    || attestation.bindingId !== expected.bindingId
    || attestation.postExploitSpecId !== expected.postExploitSpecId
    || attestation.scriptArtifactId !== expected.scriptArtifactId
    || attestation.exploitOutcomeObserverSpecId
      !== expected.exploitOutcomeObserverSpecId
    || attestation.candidateClass !== "reviewed_real_candidate_v1"
    || attestation.realTargetSupport !== true
    || !candidateLinuxTargetScopesEqual(
      parseCandidateLinuxTargetScope(attestation.targetScope),
      expected.targetScope,
    )
    || !Number.isFinite(observed)
    || !Number.isFinite(expires)
    || observed < expected.now.getTime() - 60_000
    || observed > expected.now.getTime() + 5_000
    || expires <= expected.now.getTime()
    || expires <= observed
    || expires > observed + 5 * 60_000
    || typeof attestation.receiptSha256 !== "string"
    || !SHA256.test(attestation.receiptSha256)
    || digestCanonicalJson(
      unsigned,
      { maxBytes: 64 * 1_024, maxDepth: 16 },
    ).sha256 !== attestation.receiptSha256
  ) {
    throw new Error(
      "The reviewed candidate procedure attestation is invalid",
    );
  }
  return Object.freeze({
    ...unsigned,
    schemaVersion:
      REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_ATTESTATION_SCHEMA_VERSION,
    protocolVersion:
      REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
    profileSha256: expected.profileSha256,
    procedureExecutableSha256: expected.procedureExecutableSha256,
    bindingId: expected.bindingId,
    postExploitSpecId: expected.postExploitSpecId,
    scriptArtifactId: expected.scriptArtifactId,
    exploitOutcomeObserverSpecId: expected.exploitOutcomeObserverSpecId,
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: expected.targetScope,
    operations,
    boundary,
    observedAt: String(attestation.observedAt),
    expiresAt: String(attestation.expiresAt),
    receiptSha256: attestation.receiptSha256,
  });
}

function validateConformanceCase(
  operation: CandidateLinuxTransportOperation,
  value: unknown,
  profile: ReviewedRealCandidateLinuxProfile,
): Readonly<Record<string, unknown>> {
  const label = `reviewed candidate procedure ${operation} conformance`;
  switch (operation) {
    case "open":
    case "privilege_escalation":
      exactAccepted(value, label);
      break;
    case "close":
    case "cleanup":
      exactClosed(value, label);
      break;
    case "prove_user_flag_hash":
    case "prove_root_flag_hash":
      exactProof(value, label);
      break;
    case "observe_identity": {
      const identity = plain(value, label);
      exactKeys(identity, ["gid", "groups", "principal", "uid"], label);
      if (
        identity.principal !== profile.postExploitSpec.expectedPrincipal
        || identity.uid !== profile.postExploitSpec.expectedUid
        || !Number.isSafeInteger(identity.gid)
        || Number(identity.gid) < 0
        || !Array.isArray(identity.groups)
        || identity.groups.length < 1
        || identity.groups.length > 64
        || identity.groups.some(
          (group) => typeof group !== "string" || !PRINCIPAL.test(group),
        )
        || new Set(identity.groups).size !== identity.groups.length
      ) {
        throw new Error(`${label} is not the profile-pinned identity schema`);
      }
      break;
    }
    case "observe_root_identity": {
      const identity = plain(value, label);
      exactKeys(identity, ["gid", "groups", "principal", "uid"], label);
      if (
        identity.principal !== "root"
        || identity.uid !== 0
        || identity.gid !== 0
        || !Array.isArray(identity.groups)
        || identity.groups.length < 1
        || identity.groups.length > 64
        || identity.groups.some(
          (group) => typeof group !== "string" || !PRINCIPAL.test(group),
        )
        || !identity.groups.includes("root")
      ) {
        throw new Error(`${label} is not the closed root identity schema`);
      }
      break;
    }
  }
  return Object.freeze({ ...plain(value, label) });
}

function parseConformance(
  value: unknown,
  expected: Readonly<{
    profile: ReviewedRealCandidateLinuxProfile;
    profileSha256: string;
    procedureExecutableSha256: string;
  }>,
): ReviewedRealCandidateLinuxProcedureConformance {
  const conformance = plain(
    value,
    "reviewed candidate procedure conformance",
  );
  exactKeys(conformance, [
    "bindingId",
    "cases",
    "exploitOutcomeObserverSpecId",
    "postExploitSpecId",
    "procedureExecutableSha256",
    "profileSha256",
    "protocolVersion",
    "receiptSha256",
    "schemaVersion",
    "scriptArtifactId",
    "targetScope",
  ], "reviewed candidate procedure conformance");
  const rawCases = conformance.cases;
  if (
    conformance.schemaVersion
      !== REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_CONFORMANCE_SCHEMA_VERSION
    || conformance.protocolVersion
      !== REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION
    || conformance.profileSha256 !== expected.profileSha256
    || conformance.procedureExecutableSha256
      !== expected.procedureExecutableSha256
    || conformance.bindingId !== expected.profile.bindingId
    || conformance.postExploitSpecId
      !== expected.profile.postExploitSpec.id
    || conformance.scriptArtifactId
      !== expected.profile.postExploitSpec.scriptArtifactId
    || conformance.exploitOutcomeObserverSpecId
      !== expected.profile.postExploitSpec.exploitOutcomeObserverSpecId
    || !candidateLinuxTargetScopesEqual(
      parseCandidateLinuxTargetScope(conformance.targetScope),
      expected.profile.targetScope,
    )
    || !Array.isArray(rawCases)
    || rawCases.length !== OPERATIONS.length
  ) {
    throw new Error(
      "The reviewed candidate procedure conformance identity is invalid",
    );
  }
  const cases = OPERATIONS.map((operation, index) => {
    const raw = plain(
      rawCases[index],
      `reviewed candidate procedure conformance case ${index}`,
    );
    exactKeys(
      raw,
      ["operation", "result"],
      `reviewed candidate procedure conformance case ${index}`,
    );
    if (raw.operation !== operation) {
      throw new Error(
        "The reviewed candidate procedure conformance cases are not the complete ordered closed set",
      );
    }
    return Object.freeze({
      operation,
      result: validateConformanceCase(
        operation,
        raw.result,
        expected.profile,
      ),
    });
  });
  const unsigned = Object.freeze({
    schemaVersion:
      REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_CONFORMANCE_SCHEMA_VERSION,
    protocolVersion:
      REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
    profileSha256: expected.profileSha256,
    procedureExecutableSha256: expected.procedureExecutableSha256,
    bindingId: expected.profile.bindingId,
    postExploitSpecId: expected.profile.postExploitSpec.id,
    scriptArtifactId: expected.profile.postExploitSpec.scriptArtifactId,
    exploitOutcomeObserverSpecId:
      expected.profile.postExploitSpec.exploitOutcomeObserverSpecId,
    targetScope: expected.profile.targetScope,
    cases: Object.freeze(cases),
  });
  if (
    typeof conformance.receiptSha256 !== "string"
    || !SHA256.test(conformance.receiptSha256)
    || digestCanonicalJson(
      unsigned,
      { maxBytes: 64 * 1_024, maxDepth: 16 },
    ).sha256 !== conformance.receiptSha256
  ) {
    throw new Error(
      "The reviewed candidate procedure conformance receipt is invalid",
    );
  }
  return Object.freeze({
    ...unsigned,
    receiptSha256: conformance.receiptSha256,
  });
}

export class HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider
implements ReviewedRealCandidateLinuxProcedureProvider {
  readonly profileSha256: string;
  readonly procedureExecutableSha256: string;
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly scriptArtifactId: string;
  readonly exploitOutcomeObserverSpecId: string;
  readonly candidateClass = "reviewed_real_candidate_v1" as const;
  readonly realTargetSupport = true as const;
  readonly targetScope: CandidateLinuxTargetScope;
  readonly #profile: ReviewedRealCandidateLinuxProfile;
  readonly #executablePath: string;
  readonly #allowedOwnerUids: readonly number[];
  readonly #timeoutMs: number;
  readonly #now: () => Date;
  readonly #maximumConcurrency: number;
  #active = 0;

  constructor(input: Readonly<{
    profile: ReviewedRealCandidateLinuxProfile;
    profileSha256: string;
    procedureExecutablePath: string;
    procedureExecutableSha256: string;
    allowedOwnerUids?: readonly number[];
    timeoutMs?: number;
    maximumConcurrency?: number;
    now?: () => Date;
  }>) {
    this.#profile = input.profile;
    this.profileSha256 = hash(input.profileSha256, "profileSha256");
    this.procedureExecutableSha256 = hash(
      input.procedureExecutableSha256,
      "procedureExecutableSha256",
    );
    this.bindingId = input.profile.bindingId;
    this.postExploitSpecId = input.profile.postExploitSpec.id;
    this.scriptArtifactId = input.profile.postExploitSpec.scriptArtifactId;
    this.exploitOutcomeObserverSpecId =
      input.profile.postExploitSpec.exploitOutcomeObserverSpecId;
    this.targetScope = input.profile.targetScope;
    this.#executablePath = absolutePath(
      input.procedureExecutablePath,
      "procedureExecutablePath",
    );
    const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
    this.#allowedOwnerUids = Object.freeze([
      ...new Set(input.allowedOwnerUids ?? [0, currentUid]),
    ]);
    if (
      this.#allowedOwnerUids.length < 1
      || this.#allowedOwnerUids.length > 4
      || this.#allowedOwnerUids.some((uid) =>
        !Number.isSafeInteger(uid) || uid < 0)
    ) {
      throw new TypeError("Procedure executable owner allowlist is invalid");
    }
    this.#timeoutMs = input.timeoutMs ?? 15_000;
    if (
      !Number.isSafeInteger(this.#timeoutMs)
      || this.#timeoutMs < MINIMUM_TIMEOUT_MS
      || this.#timeoutMs > MAXIMUM_TIMEOUT_MS
    ) {
      throw new RangeError("Procedure timeout is outside its reviewed bound");
    }
    this.#now = input.now ?? (() => new Date());
    this.#maximumConcurrency = input.maximumConcurrency ?? 1;
    if (
      !Number.isSafeInteger(this.#maximumConcurrency)
      || this.#maximumConcurrency < 1
      || this.#maximumConcurrency > 8
    ) {
      throw new RangeError(
        "Procedure concurrency is outside its reviewed bound",
      );
    }
    assertPinnedExecutable(
      this.#executablePath,
      this.procedureExecutableSha256,
      this.#allowedOwnerUids,
    );
    if (
      input.profile.procedure.executablePath !== this.#executablePath
      || input.profile.procedure.executableSha256
        !== this.procedureExecutableSha256
      || input.profile.procedure.protocolVersion
        !== REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION
    ) {
      throw new Error(
        "The procedure provider differs from the executable and protocol pinned by the reviewed profile",
      );
    }
  }

  async conform(
    signal: AbortSignal,
  ): Promise<ReviewedRealCandidateLinuxProcedureConformance> {
    return await this.#bounded(async () => {
      const result = await runPinnedProcedure({
        executablePath: this.#executablePath,
        executableSha256: this.procedureExecutableSha256,
        allowedOwnerUids: this.#allowedOwnerUids,
        timeoutMs: this.#timeoutMs,
        signal,
        envelope: Object.freeze({
          operation: "conformance",
          protocolVersion:
            REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
          profileSha256: this.profileSha256,
          procedureExecutableSha256: this.procedureExecutableSha256,
          bindingId: this.bindingId,
          postExploitSpecId: this.postExploitSpecId,
          scriptArtifactId: this.scriptArtifactId,
          exploitOutcomeObserverSpecId: this.exploitOutcomeObserverSpecId,
          targetScope: this.targetScope,
        }),
      });
      return parseConformance(result, {
        profile: this.#profile,
        profileSha256: this.profileSha256,
        procedureExecutableSha256: this.procedureExecutableSha256,
      });
    });
  }

  async attest(
    signal: AbortSignal,
  ): Promise<ReviewedRealCandidateLinuxProcedureAttestation> {
    return await this.#bounded(async () => {
      const result = await runPinnedProcedure({
        executablePath: this.#executablePath,
        executableSha256: this.procedureExecutableSha256,
        allowedOwnerUids: this.#allowedOwnerUids,
        timeoutMs: this.#timeoutMs,
        signal,
        envelope: Object.freeze({
          operation: "attest",
          protocolVersion:
            REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
          profileSha256: this.profileSha256,
          procedureExecutableSha256: this.procedureExecutableSha256,
          bindingId: this.bindingId,
          postExploitSpecId: this.postExploitSpecId,
          scriptArtifactId: this.scriptArtifactId,
          exploitOutcomeObserverSpecId: this.exploitOutcomeObserverSpecId,
          targetScope: this.targetScope,
        }),
      });
      return parseAttestation(result, {
        profileSha256: this.profileSha256,
        procedureExecutableSha256: this.procedureExecutableSha256,
        bindingId: this.bindingId,
        postExploitSpecId: this.postExploitSpecId,
        scriptArtifactId: this.scriptArtifactId,
        exploitOutcomeObserverSpecId: this.exploitOutcomeObserverSpecId,
        targetScope: this.targetScope,
        now: this.#now(),
      });
    });
  }

  async invoke(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown> {
    if (!candidateLinuxTargetScopeMatches(this.targetScope, request.exactTarget)) {
      throw new Error(
        "The reviewed candidate procedure is unavailable for this exact target",
      );
    }
    return await this.#bounded(async () =>
      await runPinnedProcedure({
        executablePath: this.#executablePath,
        executableSha256: this.procedureExecutableSha256,
        allowedOwnerUids: this.#allowedOwnerUids,
        timeoutMs: this.#timeoutMs,
        signal,
        envelope: Object.freeze({
          operation: "invoke",
          protocolVersion:
            REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
          profileSha256: this.profileSha256,
          procedureExecutableSha256: this.procedureExecutableSha256,
          bindingId: this.bindingId,
          postExploitSpecId: this.postExploitSpecId,
          scriptArtifactId: this.scriptArtifactId,
          exploitOutcomeObserverSpecId: this.exploitOutcomeObserverSpecId,
          targetScope: this.targetScope,
          request,
        }),
      }),
    );
  }

  async #bounded<T>(operation: () => Promise<T>): Promise<T> {
    if (this.#active >= this.#maximumConcurrency) {
      throw new Error(
        "The reviewed candidate procedure reached its concurrency bound",
      );
    }
    this.#active += 1;
    try {
      return await operation();
    } finally {
      this.#active -= 1;
    }
  }
}

function receipt<T extends Readonly<Record<string, unknown>>>(
  input: T,
  field: string,
): Readonly<T & Record<string, string>> {
  return Object.freeze({
    ...input,
    [field]: digestCanonicalJson(
      input,
      { maxBytes: 32 * 1_024, maxDepth: 12 },
    ).sha256,
  });
}

function exactProof(
  value: unknown,
  label: string,
): Readonly<{ sha256: string; byteSize: number }> {
  const proof = plain(value, label);
  exactKeys(proof, ["byteSize", "sha256"], label);
  if (
    typeof proof.sha256 !== "string"
    || !SHA256.test(proof.sha256)
    || !Number.isSafeInteger(proof.byteSize)
    || Number(proof.byteSize) < 1
    || Number(proof.byteSize) > 4_096
  ) {
    throw new Error(`${label} is not a bounded hash-only proof`);
  }
  return Object.freeze({
    sha256: proof.sha256,
    byteSize: Number(proof.byteSize),
  });
}

function exactAccepted(value: unknown, label: string): void {
  const response = plain(value, label);
  exactKeys(response, ["accepted"], label);
  if (response.accepted !== true) {
    throw new Error(`${label} did not acknowledge the exact operation`);
  }
}

function exactClosed(value: unknown, label: string): void {
  const response = plain(value, label);
  exactKeys(response, ["closed"], label);
  if (response.closed !== true) {
    throw new Error(`${label} did not confirm bounded cleanup`);
  }
}

export class ProcedureBackedReviewedRealCandidateLinuxAdapterImplementation
implements ReviewedRealCandidateLinuxAdapterImplementation {
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly profileSha256: string;
  readonly adapterExecutableSha256: string;
  readonly candidateClass = "reviewed_real_candidate_v1" as const;
  readonly realTargetSupport = true as const;
  readonly targetScope: CandidateLinuxTargetScope;
  readonly #profile: ReviewedRealCandidateLinuxProfile;
  readonly #provider: ReviewedRealCandidateLinuxProcedureProvider;
  readonly #now: () => Date;

  constructor(input: Readonly<{
    profile: ReviewedRealCandidateLinuxProfile;
    profileSha256: string;
    adapterExecutableSha256: string;
    provider: ReviewedRealCandidateLinuxProcedureProvider;
    now?: () => Date;
  }>) {
    this.#profile = input.profile;
    this.bindingId = input.profile.bindingId;
    this.postExploitSpecId = input.profile.postExploitSpec.id;
    this.profileSha256 = hash(input.profileSha256, "profileSha256");
    this.adapterExecutableSha256 = hash(
      input.adapterExecutableSha256,
      "adapterExecutableSha256",
    );
    this.targetScope = input.profile.targetScope;
    this.#provider = input.provider;
    this.#now = input.now ?? (() => new Date());
    if (
      this.#provider.profileSha256 !== this.profileSha256
      || this.#provider.bindingId !== this.bindingId
      || this.#provider.postExploitSpecId !== this.postExploitSpecId
      || this.#provider.scriptArtifactId
        !== input.profile.postExploitSpec.scriptArtifactId
      || this.#provider.exploitOutcomeObserverSpecId
        !== input.profile.postExploitSpec.exploitOutcomeObserverSpecId
      || this.#provider.candidateClass !== "reviewed_real_candidate_v1"
      || this.#provider.realTargetSupport !== true
      || !candidateLinuxTargetScopesEqual(
        this.#provider.targetScope,
        input.profile.targetScope,
      )
    ) {
      throw new Error(
        "The reviewed candidate procedure provider does not match the profile authority",
      );
    }
  }

  async attest(signal: AbortSignal): Promise<void> {
    await this.#provider.attest(signal);
  }

  async handle(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown> {
    if (
      request.transportBindingId !== this.bindingId
      || request.postExploitSpecId === this.postExploitSpecId
      || !ID.test(request.postExploitSpecId)
      || isIP(request.exactTarget) === 0
      || !candidateLinuxTargetScopeMatches(
        this.targetScope,
        request.exactTarget,
      )
    ) {
      throw new Error(
        "The reviewed candidate request is outside the bound profile identity",
      );
    }
    if ("candidateBindingHash" in request) {
      hash(request.candidateBindingHash, "candidateBindingHash");
      if (
        !Number.isSafeInteger(request.leaseFencingToken)
        || request.leaseFencingToken < 1
      ) {
        throw new Error("The reviewed candidate request lease fence is invalid");
      }
    }
    const result = await this.#provider.invoke(request, signal);
    const observedAt = this.#now().toISOString();
    switch (request.operation) {
      case "open":
        exactAccepted(result, "candidate procedure open result");
        return Object.freeze({
          accepted: true,
          sessionArtifactId: request.sessionArtifactId,
        });
      case "observe_identity": {
        const identity = plain(result, "candidate procedure identity result");
        exactKeys(
          identity,
          ["gid", "groups", "principal", "uid"],
          "candidate procedure identity result",
        );
        if (
          identity.principal !== this.#profile.postExploitSpec.expectedPrincipal
          || identity.uid !== this.#profile.postExploitSpec.expectedUid
          || !Number.isSafeInteger(identity.gid)
          || Number(identity.gid) < 0
          || !Array.isArray(identity.groups)
          || identity.groups.length > 64
          || identity.groups.some(
            (group) => typeof group !== "string" || !PRINCIPAL.test(group),
          )
          || new Set(identity.groups).size !== identity.groups.length
        ) {
          throw new Error(
            "The candidate procedure identity differs from the reviewed principal",
          );
        }
        return Object.freeze({
          sessionArtifactId: request.sessionArtifactId,
          principal: identity.principal,
          uid: identity.uid,
          gid: Number(identity.gid),
          groups: Object.freeze([...(identity.groups as string[])]),
        });
      }
      case "prove_user_flag_hash": {
        if (
          request.declaredPath
            !== this.#profile.postExploitSpec.declaredUserFlagPath
        ) {
          throw new Error("The candidate user proof path is not profile-pinned");
        }
        const proof = exactProof(
          result,
          "candidate procedure user proof result",
        );
        return Object.freeze({
          sessionArtifactId: request.sessionArtifactId,
          declaredPath: request.declaredPath,
          sha256: proof.sha256,
          byteSize: proof.byteSize,
        });
      }
      case "close":
        exactClosed(result, "candidate procedure close result");
        return Object.freeze({
          closed: true,
          sessionArtifactId: request.sessionArtifactId,
        });
      case "privilege_escalation":
        exactAccepted(result, "candidate procedure privilege result");
        return receipt({
          schemaVersion: LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
          sessionArtifactId: request.sessionArtifactId,
          accepted: true as const,
          observedAt,
        }, "receiptSha256");
      case "observe_root_identity": {
        const identity = plain(
          result,
          "candidate procedure root identity result",
        );
        exactKeys(
          identity,
          ["gid", "groups", "principal", "uid"],
          "candidate procedure root identity result",
        );
        if (
          identity.principal !== "root"
          || identity.uid !== 0
          || identity.gid !== 0
          || !Array.isArray(identity.groups)
          || identity.groups.length < 1
          || identity.groups.length > 64
          || identity.groups.some(
            (group) => typeof group !== "string" || !PRINCIPAL.test(group),
          )
        ) {
          throw new Error(
            "The candidate procedure did not independently observe root identity",
          );
        }
        return receipt({
          schemaVersion: LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
          sessionArtifactId: request.sessionArtifactId,
          principal: "root" as const,
          uid: 0 as const,
          gid: 0 as const,
          groups: Object.freeze([...(identity.groups as string[])]),
          observedAt,
        }, "observationSha256");
      }
      case "prove_root_flag_hash": {
        if (request.declaredPath !== "/root/root.txt") {
          throw new Error("The candidate root proof path is not profile-pinned");
        }
        const proof = exactProof(
          result,
          "candidate procedure root proof result",
        );
        return receipt({
          schemaVersion: LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
          sessionArtifactId: request.sessionArtifactId,
          declaredPath: "/root/root.txt" as const,
          contentSha256: proof.sha256,
          byteSize: proof.byteSize,
          observedAt,
        }, "proofSha256");
      }
      case "cleanup":
        exactClosed(result, "candidate procedure cleanup result");
        return receipt({
          schemaVersion: LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
          sessionArtifactId: request.sessionArtifactId,
          closed: true as const,
          observedAt,
        }, "receiptSha256");
    }
  }
}

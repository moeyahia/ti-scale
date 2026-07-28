import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { createConnection, isIP, type Socket } from "node:net";
import { isAbsolute, resolve, sep } from "node:path";
import type { SqliteDatabase } from "../db";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";
import {
  AUTONOMOUS_LINUX_SESSION_IDENTITY_ACTION_TYPE,
  AUTONOMOUS_LINUX_USER_FLAG_PROOF_ACTION_TYPE,
  type
  CandidateRuntimeLinuxSessionRequest,
  type CandidateRuntimeLinuxSessionTransport,
} from "./AutonomousLinuxPostExploitSession";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  type
  CandidateRuntimeLinuxPrivilegeRequest,
  type CandidateRuntimeLinuxPrivilegeTransport,
} from "./CandidateLinuxPrivilegeContinuation";
import {
  candidateLinuxPostExploitSpecificationHash,
} from "./CandidateLinuxPostExploitSpecRegistry";

export const CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION =
  "ti-scale.candidate-linux-transport-binding-manifest.v1" as const;
export const CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION =
  "ti-scale.candidate-linux-transport.v1" as const;
export const CANDIDATE_LINUX_TRANSPORT_ATTESTATION_SCHEMA_VERSION =
  "ti-scale.candidate-linux-transport-attestation.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u;
const VERSION = /^[A-Za-z0-9._-]{1,80}$/u;
const CONTROL = /[\u0000-\u001F\u007F]/u;
const MAXIMUM_RESPONSE_BYTES = 64 * 1024;
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
export type CandidateLinuxTransportOperation = typeof OPERATIONS[number];

export interface CandidateLinuxTransportBindingManifest {
  readonly schemaVersion:
    typeof CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION;
  readonly bundleVersion: string;
  readonly broker: Readonly<{
    readonly executablePath: string;
    readonly executableSha256: string;
    readonly socketPath: string;
    readonly socketGid: number;
    readonly protocolVersion: typeof CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION;
  }>;
  readonly boundary: Readonly<{
    readonly typedOperationsOnly: true;
    readonly genericCommand: false;
    readonly shell: false;
    readonly argv: false;
    readonly payload: false;
    readonly credentials: false;
    readonly exactTargetFromCanonicalAction: true;
    readonly succeededAttackAttemptRequired: true;
    readonly publicProvider: false;
  }>;
  readonly bindings: readonly Readonly<{
    readonly bindingId: string;
    readonly postExploitSpecId: string;
    readonly postExploitSpecSha256: string;
    /**
     * The first production-path transport is intentionally a harmless local
     * candidate. A different candidate class requires a new reviewed schema;
     * this field cannot be reinterpreted as generic target support.
     */
    readonly candidateClass:
      | "disposable_local_fixture_v1"
      | "reviewed_real_candidate_v1";
    readonly handlerProfilePath: string;
    readonly handlerProfileSha256: string;
    readonly realTargetSupport: boolean;
    readonly operations: readonly CandidateLinuxTransportOperation[];
  }>[];
}

export interface CandidateLinuxTransportAttestation {
  readonly schemaVersion:
    typeof CANDIDATE_LINUX_TRANSPORT_ATTESTATION_SCHEMA_VERSION;
  readonly protocolVersion: typeof CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION;
  readonly manifestSha256: string;
  readonly brokerExecutableSha256: string;
  readonly bindingIds: readonly string[];
  readonly bindingCapabilities: readonly Readonly<{
    readonly bindingId: string;
    readonly candidateClass:
      | "disposable_local_fixture_v1"
      | "reviewed_real_candidate_v1";
    readonly realTargetSupport: boolean;
  }>[];
  readonly boundary: CandidateLinuxTransportBindingManifest["boundary"];
  readonly grantsMissionExecution: false;
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly receiptSha256: string;
}

export interface CandidateLinuxTransportReadiness {
  readonly status: "ready" | "blocked";
  readonly code: "candidate_linux_transport_ready"
    | "candidate_linux_transport_unavailable";
  readonly reason: string;
  readonly manifestSha256: string;
  readonly bindingIds: readonly string[];
  readonly bindingCapabilities:
    CandidateLinuxTransportAttestation["bindingCapabilities"];
  readonly readinessScope:
    | "production_path_proof_only"
    | "reviewed_real_candidate";
  /** True only when the current attestation can be projected into a mission. */
  readonly missionExecutionReady: boolean;
  readonly expiresAt: string | null;
}

function plain(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
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
  if (actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])) {
    throw new TypeError(`${label} must contain exactly: ${canonical.join(", ")}`);
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

function absolutePath(value: unknown, label: string): string {
  if (typeof value !== "string" || value !== value.trim()
    || !isAbsolute(value) || value === resolve(sep)
    || value.length > 4_096 || CONTROL.test(value)) {
    throw new TypeError(`${label} must be a safe absolute path`);
  }
  return resolve(value);
}

function exactBoolean(
  value: unknown,
  expected: boolean,
  label: string,
): boolean {
  if (value !== expected) {
    throw new TypeError(`${label} must equal ${String(expected)}`);
  }
  return expected;
}

export function parseCandidateLinuxTransportBindingManifest(
  input: unknown,
): CandidateLinuxTransportBindingManifest {
  const root = plain(input, "candidate transport manifest");
  exactKeys(
    root,
    ["bindings", "boundary", "broker", "bundleVersion", "schemaVersion"],
    "candidate transport manifest",
  );
  if (root.schemaVersion
    !== CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION) {
    throw new TypeError("Unsupported candidate Linux transport manifest");
  }
  if (typeof root.bundleVersion !== "string"
    || !VERSION.test(root.bundleVersion)) {
    throw new TypeError("bundleVersion must be stable");
  }
  const broker = plain(root.broker, "broker");
  exactKeys(
    broker,
    ["executablePath", "executableSha256", "protocolVersion", "socketGid", "socketPath"],
    "broker",
  );
  if (broker.protocolVersion !== CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION) {
    throw new TypeError("Unsupported candidate Linux transport protocol");
  }
  if (!Number.isSafeInteger(broker.socketGid)
    || (broker.socketGid as number) < 0) {
    throw new TypeError("broker.socketGid must be a non-negative integer");
  }
  const boundary = plain(root.boundary, "boundary");
  exactKeys(boundary, [
    "argv",
    "credentials",
    "exactTargetFromCanonicalAction",
    "genericCommand",
    "payload",
    "publicProvider",
    "shell",
    "succeededAttackAttemptRequired",
    "typedOperationsOnly",
  ], "boundary");
  if (!Array.isArray(root.bindings)
    || root.bindings.length < 1 || root.bindings.length > 64) {
    throw new TypeError("bindings must contain one through 64 entries");
  }
  const bindings = root.bindings.map((raw, index) => {
    const binding = plain(raw, `bindings[${index}]`);
    exactKeys(binding, [
      "bindingId",
      "candidateClass",
      "handlerProfilePath",
      "handlerProfileSha256",
      "operations",
      "postExploitSpecId",
      "postExploitSpecSha256",
      "realTargetSupport",
    ], `bindings[${index}]`);
    if (
      binding.candidateClass !== "disposable_local_fixture_v1"
      && binding.candidateClass !== "reviewed_real_candidate_v1"
    ) {
      throw new TypeError(
        `bindings[${index}].candidateClass is unsupported`,
      );
    }
    if (
      typeof binding.realTargetSupport !== "boolean"
      || (
        binding.candidateClass === "disposable_local_fixture_v1"
          ? binding.realTargetSupport !== false
          : binding.realTargetSupport !== true
      )
    ) {
      throw new TypeError(
        `bindings[${index}] candidate class and real-target capability disagree`,
      );
    }
    if (!Array.isArray(binding.operations)
      || binding.operations.length !== OPERATIONS.length
      || binding.operations.some((operation, operationIndex) =>
        operation !== OPERATIONS[operationIndex])) {
      throw new TypeError(
        `bindings[${index}].operations must be the complete ordered typed operation set`,
      );
    }
    return Object.freeze({
      bindingId: stableId(binding.bindingId, `bindings[${index}].bindingId`),
      postExploitSpecId: stableId(
        binding.postExploitSpecId,
        `bindings[${index}].postExploitSpecId`,
      ),
      postExploitSpecSha256: hash(
        binding.postExploitSpecSha256,
        `bindings[${index}].postExploitSpecSha256`,
      ),
      candidateClass: binding.candidateClass,
      handlerProfilePath: absolutePath(
        binding.handlerProfilePath,
        `bindings[${index}].handlerProfilePath`,
      ),
      handlerProfileSha256: hash(
        binding.handlerProfileSha256,
        `bindings[${index}].handlerProfileSha256`,
      ),
      realTargetSupport: binding.realTargetSupport,
      operations: OPERATIONS,
    });
  });
  if (new Set(bindings.map((binding) => binding.bindingId)).size
    !== bindings.length
    || new Set(bindings.map((binding) => binding.postExploitSpecId)).size
      !== bindings.length) {
    throw new TypeError("Candidate Linux transport bindings must be unique");
  }
  return Object.freeze({
    schemaVersion:
      CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
    bundleVersion: root.bundleVersion,
    broker: Object.freeze({
      executablePath: absolutePath(broker.executablePath, "broker.executablePath"),
      executableSha256: hash(
        broker.executableSha256,
        "broker.executableSha256",
      ),
      socketPath: absolutePath(broker.socketPath, "broker.socketPath"),
      socketGid: broker.socketGid as number,
      protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
    }),
    boundary: Object.freeze({
      typedOperationsOnly: exactBoolean(
        boundary.typedOperationsOnly, true, "boundary.typedOperationsOnly",
      ) as true,
      genericCommand: exactBoolean(
        boundary.genericCommand, false, "boundary.genericCommand",
      ) as false,
      shell: exactBoolean(boundary.shell, false, "boundary.shell") as false,
      argv: exactBoolean(boundary.argv, false, "boundary.argv") as false,
      payload: exactBoolean(boundary.payload, false, "boundary.payload") as false,
      credentials: exactBoolean(
        boundary.credentials, false, "boundary.credentials",
      ) as false,
      exactTargetFromCanonicalAction: exactBoolean(
        boundary.exactTargetFromCanonicalAction,
        true,
        "boundary.exactTargetFromCanonicalAction",
      ) as true,
      succeededAttackAttemptRequired: exactBoolean(
        boundary.succeededAttackAttemptRequired,
        true,
        "boundary.succeededAttackAttemptRequired",
      ) as true,
      publicProvider: exactBoolean(
        boundary.publicProvider, false, "boundary.publicProvider",
      ) as false,
    }),
    bindings: Object.freeze(bindings),
  });
}

export function loadTrustedCandidateLinuxTransportBindingManifest(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<CandidateLinuxTransportBindingManifest> {
  return loadTrustedJson(
    { ...reference, maximumBytes: reference.maximumBytes ?? 64 * 1024 },
    parseCandidateLinuxTransportBindingManifest,
  );
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function assertPinnedBroker(
  manifest: CandidateLinuxTransportBindingManifest,
): void {
  const metadata = lstatSync(manifest.broker.executablePath);
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  if (!metadata.isFile() || metadata.isSymbolicLink()
    || ![0, currentUid].includes(metadata.uid)
    || (metadata.mode & 0o022) !== 0
    || sha256File(manifest.broker.executablePath)
      !== manifest.broker.executableSha256) {
    throw new Error(
      "Candidate Linux transport broker is not owner-controlled and hash-pinned",
    );
  }
}

function responseTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${label} must be an ISO timestamp`);
  }
  return value;
}

async function unixRequest(
  socketPath: string,
  socketGid: number,
  request: Readonly<Record<string, unknown>>,
  signal: AbortSignal,
): Promise<unknown> {
  const socketMetadata = lstatSync(socketPath);
  if (!socketMetadata.isSocket() || socketMetadata.isSymbolicLink()
    || socketMetadata.gid !== socketGid || (socketMetadata.mode & 0o002) !== 0) {
    throw new Error("Candidate Linux transport socket ownership is invalid");
  }
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
    const abort = () => finish(new Error("Candidate Linux transport request cancelled"));
    if (signal.aborted) return abort();
    signal.addEventListener("abort", abort, { once: true });
    socket = createConnection({ path: socketPath });
    socket.setTimeout(5_000);
    socket.on("connect", () => {
      socket?.write(`${JSON.stringify(request)}\n`);
    });
    socket.on("data", (chunk) => {
      response += chunk.toString("utf8");
      if (Buffer.byteLength(response, "utf8") > MAXIMUM_RESPONSE_BYTES) {
        return finish(new Error("Candidate Linux transport response exceeded its bound"));
      }
      const newline = response.indexOf("\n");
      if (newline < 0) return;
      try {
        const envelope = plain(
          JSON.parse(response.slice(0, newline)) as unknown,
          "broker response",
        );
        exactKeys(envelope, envelope.ok === true
          ? ["ok", "result"]
          : ["error", "ok"], "broker response");
        if (envelope.ok !== true) {
          const failure = plain(envelope.error, "broker error");
          throw new Error(
            typeof failure.message === "string"
              ? failure.message
              : "Candidate Linux transport rejected the operation",
          );
        }
        finish(undefined, envelope.result);
      } catch (error) {
        finish(error instanceof Error ? error : new Error(String(error)));
      }
    });
    socket.on("timeout", () => finish(new Error("Candidate Linux transport timed out")));
    socket.on("error", (error) => finish(error));
    socket.on("end", () => {
      if (!settled) finish(new Error("Candidate Linux transport closed without a response"));
    });
  });
}

export type CandidateLinuxTransportRequest =
  | CandidateRuntimeLinuxSessionRequest
  | CandidateRuntimeLinuxPrivilegeRequest;

export interface CandidateLinuxTransportCanonicalAuthorizer {
  authorize(
    request: CandidateLinuxTransportRequest,
  ): CandidateLinuxTransportOperation;
}

function assertTypedRequest(
  value: CandidateLinuxTransportRequest,
): CandidateLinuxTransportOperation {
  const request = plain(value, "candidate Linux transport request");
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
    exactKeys(request, common, "candidate Linux session request");
  } else if (operation === "prove_user_flag_hash") {
    exactKeys(
      request,
      [...common, "declaredPath"],
      "candidate Linux user proof request",
    );
    if (
      typeof request.declaredPath !== "string"
      || !/^\/home\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\/user\.txt$/u
        .test(request.declaredPath)
    ) {
      throw new Error("Candidate Linux user proof path is outside the typed boundary");
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
    ], "candidate Linux privilege request");
  } else if (operation === "prove_root_flag_hash") {
    exactKeys(request, [
      ...common,
      "actionId",
      "candidateBindingHash",
      "declaredPath",
      "leaseFencingToken",
    ], "candidate Linux root proof request");
    if (request.declaredPath !== "/root/root.txt") {
      throw new Error("Candidate Linux root proof path is outside the typed boundary");
    }
  } else if (operation === "cleanup") {
    exactKeys(request, [
      ...common,
      "candidateBindingHash",
      "leaseFencingToken",
      "reason",
    ], "candidate Linux cleanup request");
    if (
      typeof request.reason !== "string"
      || request.reason !== request.reason.trim()
      || request.reason.length < 1
      || request.reason.length > 300
      || CONTROL.test(request.reason)
    ) {
      throw new Error("Candidate Linux cleanup reason is outside the typed boundary");
    }
  } else {
    throw new Error("Candidate Linux transport operation is outside the typed boundary");
  }
  stableId(request.transportBindingId, "request.transportBindingId");
  stableId(request.postExploitSpecId, "request.postExploitSpecId");
  stableId(request.sessionArtifactId, "request.sessionArtifactId");
  if (typeof request.exactTarget !== "string" || isIP(request.exactTarget) === 0) {
    throw new Error("Candidate Linux transport requires one canonical IP target");
  }
  if ("candidateBindingHash" in request) {
    hash(request.candidateBindingHash, "request.candidateBindingHash");
    if (typeof request.leaseFencingToken !== "number"
      || !Number.isSafeInteger(request.leaseFencingToken)
      || request.leaseFencingToken < 1) {
      throw new Error("Candidate Linux transport lease fence is invalid");
    }
  }
  if ("actionId" in request) stableId(request.actionId, "request.actionId");
  return operation;
}

/**
 * Production transport for candidate-bound post-exploit work. Every request
 * is selected from a closed typed union. The registry cannot carry a command,
 * argv, shell, payload, credential, arbitrary file read, or target override.
 */
export class CandidateLinuxTransportBindingRegistry
implements CandidateRuntimeLinuxSessionTransport,
CandidateRuntimeLinuxPrivilegeTransport,
CandidateLinuxTransportCanonicalAuthorizer {
  private attestation?: CandidateLinuxTransportAttestation;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    loadedManifest: LoadedTrustedJson<CandidateLinuxTransportBindingManifest>;
    now?: () => Date;
  }>) {
    assertPinnedBroker(options.loadedManifest.value);
  }

  private databaseBindingsCurrent(): boolean {
    return this.options.loadedManifest.value.bindings.every((binding) => {
      const spec = this.options.database.prepare(`
        SELECT spec_hash, transport_binding_id, transport_type, status
        FROM candidate_linux_post_exploit_specs WHERE id = ?
      `).get(binding.postExploitSpecId) as {
        readonly spec_hash: string;
        readonly transport_binding_id: string;
        readonly transport_type: string;
        readonly status: string;
      } | undefined;
      return spec?.status === "active"
        && spec.transport_type === "candidate_runtime_session_v1"
        && spec.transport_binding_id === binding.bindingId
        && spec.spec_hash === binding.postExploitSpecSha256;
    });
  }

  /**
   * A manifest pins one operator-reviewed source specification. Runtime
   * materialization creates a new current-run ScriptArtifact and observer ID,
   * so the cloned specification has a different ID/hash. Accept that clone
   * only when every executable and observational property is byte-identical,
   * its source lineage is explicit, and its own hash recomputes exactly.
   */
  private requestSpecMatchesBinding(
    binding: CandidateLinuxTransportBindingManifest["bindings"][number],
    requestedSpecId: string,
  ): boolean {
    if (requestedSpecId === binding.postExploitSpecId) {
      // A reviewed real-candidate source is an immutable template. Execution
      // must use the byte-identical current-run clone so mission/run custody is
      // explicit; disposable proof bindings retain their exact-source path.
      if (
        binding.candidateClass === "reviewed_real_candidate_v1"
        && binding.realTargetSupport === true
      ) {
        return false;
      }
      const source = this.options.database.prepare(`
        SELECT spec.spec_hash, spec.transport_binding_id,
          spec.transport_type, spec.transport_origin, spec.status,
          spec.exploit_outcome_observer_spec_id AS observer_id,
          spec.script_artifact_id AS script_id,
          spec.expected_principal, spec.expected_uid,
          spec.declared_user_flag_path,
          script.content_hash AS script_hash,
          script.validation_state AS script_validation_state,
          observer.script_content_hash AS observer_script_hash,
          observer.status AS observer_status
        FROM candidate_linux_post_exploit_specs spec
        JOIN script_artifacts script
          ON script.id = spec.script_artifact_id
        JOIN exploit_outcome_observer_specs observer
          ON observer.id = spec.exploit_outcome_observer_spec_id
          AND observer.script_artifact_id = script.id
        WHERE spec.id = ?
        LIMIT 1
      `).get(requestedSpecId) as
        | Readonly<Record<string, string | number | null>>
        | undefined;
      if (!source) return false;
      const expectedSourceHash =
        candidateLinuxPostExploitSpecificationHash({
          exploitOutcomeObserverSpecId: String(source.observer_id),
          scriptArtifactId: String(source.script_id),
          scriptContentHash: String(source.script_hash),
          transportType: "candidate_runtime_session_v1",
          transportBindingId: binding.bindingId,
          transportOrigin: null,
          expectedPrincipal: String(source.expected_principal),
          expectedUid: Number(source.expected_uid),
          declaredUserFlagPath: String(source.declared_user_flag_path),
        });
      return source?.spec_hash === binding.postExploitSpecSha256
        && source.spec_hash === expectedSourceHash
        && source.transport_binding_id === binding.bindingId
        && source.transport_type === "candidate_runtime_session_v1"
        && source.transport_origin === null
        && source.status === "active"
        && source.script_validation_state === "approved"
        && source.observer_status === "active"
        && source.observer_script_hash === source.script_hash;
    }
    if (
      binding.candidateClass !== "reviewed_real_candidate_v1"
      || binding.realTargetSupport !== true
    ) {
      return false;
    }
    const row = this.options.database.prepare(`
      SELECT
        derived.id AS derived_id,
        derived.exploit_outcome_observer_spec_id AS derived_observer_id,
        derived.script_artifact_id AS derived_script_id,
        derived.transport_type AS derived_transport_type,
        derived.transport_binding_id AS derived_binding_id,
        derived.transport_origin AS derived_origin,
        derived.expected_principal AS derived_principal,
        derived.expected_uid AS derived_uid,
        derived.declared_user_flag_path AS derived_user_path,
        derived.declared_root_flag_path AS derived_root_path,
        derived.spec_hash AS derived_hash,
        derived.status AS derived_status,
        derived.created_by AS derived_created_by,
        derived_script.content_hash AS derived_script_hash,
        derived_script.validation_state AS derived_script_validation_state,
        derived_observer.script_content_hash AS derived_observer_script_hash,
        derived_observer.cve_id AS derived_cve_id,
        derived_observer.observer_type AS derived_observer_type,
        derived_observer.request_json AS derived_request_json,
        derived_observer.assertion_json AS derived_assertion_json,
        derived_observer.status AS derived_observer_status,
        source.id AS source_id,
        source.exploit_outcome_observer_spec_id AS source_observer_id,
        source.script_artifact_id AS source_script_id,
        source.transport_type AS source_transport_type,
        source.transport_binding_id AS source_binding_id,
        source.transport_origin AS source_origin,
        source.expected_principal AS source_principal,
        source.expected_uid AS source_uid,
        source.declared_user_flag_path AS source_user_path,
        source.declared_root_flag_path AS source_root_path,
        source.spec_hash AS source_hash,
        source.status AS source_status,
        source_script.content_hash AS source_script_hash,
        source_script.validation_state AS source_script_validation_state,
        source_observer.script_content_hash AS source_observer_script_hash,
        source_observer.cve_id AS source_cve_id,
        source_observer.observer_type AS source_observer_type,
        source_observer.request_json AS source_request_json,
        source_observer.assertion_json AS source_assertion_json,
        source_observer.status AS source_observer_status
      FROM candidate_linux_post_exploit_specs derived
      JOIN script_artifacts derived_script
        ON derived_script.id = derived.script_artifact_id
      JOIN exploit_outcome_observer_specs derived_observer
        ON derived_observer.id = derived.exploit_outcome_observer_spec_id
        AND derived_observer.script_artifact_id = derived_script.id
      JOIN candidate_linux_post_exploit_specs source
        ON source.id = ?
      JOIN script_artifacts source_script
        ON source_script.id = source.script_artifact_id
      JOIN exploit_outcome_observer_specs source_observer
        ON source_observer.id = source.exploit_outcome_observer_spec_id
        AND source_observer.script_artifact_id = source_script.id
      WHERE derived.id = ?
      LIMIT 1
    `).get(binding.postExploitSpecId, requestedSpecId) as
      | Readonly<Record<string, string | number | null>>
      | undefined;
    if (!row) return false;
    const expectedDerivedHash =
      candidateLinuxPostExploitSpecificationHash({
        exploitOutcomeObserverSpecId: String(row.derived_observer_id),
        scriptArtifactId: String(row.derived_script_id),
        scriptContentHash: String(row.derived_script_hash),
        transportType: "candidate_runtime_session_v1",
        transportBindingId: binding.bindingId,
        transportOrigin: null,
        expectedPrincipal: String(row.derived_principal),
        expectedUid: Number(row.derived_uid),
        declaredUserFlagPath: String(row.derived_user_path),
      });
    const expectedSourceHash =
      candidateLinuxPostExploitSpecificationHash({
        exploitOutcomeObserverSpecId: String(row.source_observer_id),
        scriptArtifactId: String(row.source_script_id),
        scriptContentHash: String(row.source_script_hash),
        transportType: "candidate_runtime_session_v1",
        transportBindingId: binding.bindingId,
        transportOrigin: null,
        expectedPrincipal: String(row.source_principal),
        expectedUid: Number(row.source_uid),
        declaredUserFlagPath: String(row.source_user_path),
      });
    return row.source_id === binding.postExploitSpecId
      && row.source_hash === binding.postExploitSpecSha256
      && row.source_hash === expectedSourceHash
      && row.source_status === "active"
      && row.derived_status === "active"
      && row.source_script_validation_state === "approved"
      && row.derived_script_validation_state === "approved"
      && row.source_transport_type === "candidate_runtime_session_v1"
      && row.derived_transport_type === "candidate_runtime_session_v1"
      && row.source_binding_id === binding.bindingId
      && row.derived_binding_id === binding.bindingId
      && row.source_origin === null
      && row.derived_origin === null
      && row.derived_created_by
        === `system:cloned-from:${binding.postExploitSpecId}`
      && row.source_script_hash === row.derived_script_hash
      && row.source_observer_script_hash === row.source_script_hash
      && row.derived_observer_script_hash === row.derived_script_hash
      && row.source_observer_status === "active"
      && row.derived_observer_status === "active"
      && row.source_cve_id === row.derived_cve_id
      && row.source_observer_type === row.derived_observer_type
      && row.source_request_json === row.derived_request_json
      && row.source_assertion_json === row.derived_assertion_json
      && row.source_principal === row.derived_principal
      && row.source_uid === row.derived_uid
      && row.source_user_path === row.derived_user_path
      && row.source_root_path === "/root/root.txt"
      && row.derived_root_path === "/root/root.txt"
      && row.derived_hash === expectedDerivedHash;
  }

  /**
   * Reports whether a source or current-run derived specification is still
   * bound to the reviewed manifest. This is deliberately narrower than
   * mission authorization: `authorize` must also prove the current action,
   * contract, exact target, successful originating attempt, and session
   * fence.
   */
  acceptsPostExploitSpec(
    transportBindingId: string,
    postExploitSpecId: string,
  ): boolean {
    const binding = this.options.loadedManifest.value.bindings.find(
      (candidate) => candidate.bindingId === transportBindingId,
    );
    return Boolean(
      binding
      && ID.test(postExploitSpecId)
      && this.requestSpecMatchesBinding(binding, postExploitSpecId),
    );
  }

  private canonicalRequestCurrent(
    request: CandidateLinuxTransportRequest,
    operation: CandidateLinuxTransportOperation,
  ): boolean {
    if (
      operation === "open"
      || operation === "observe_identity"
      || operation === "prove_user_flag_hash"
    ) {
      const actionType = operation === "prove_user_flag_hash"
        ? AUTONOMOUS_LINUX_USER_FLAG_PROOF_ACTION_TYPE
        : AUTONOMOUS_LINUX_SESSION_IDENTITY_ACTION_TYPE;
      const actionClass = operation === "prove_user_flag_hash"
        ? "data_access_impact_validation"
        : "command_session_execution";
      return Boolean(this.options.database.prepare(`
        SELECT 1 AS present
        FROM actions action
        JOIN plan_steps step ON step.id = action.step_id
        JOIN runs run ON run.id = action.run_id
          AND run.mission_id = action.mission_id
          AND run.current_plan_id = step.plan_id
          AND run.journey = 'autonomous'
          AND run.control_plane = 'ti_scale'
        JOIN missions mission ON mission.id = action.mission_id
          AND mission.control_plane = 'ti_scale'
          AND mission.authorization_status = 'verified'
        JOIN mission_contracts contract ON contract.id = run.contract_id
          AND contract.id = action.contract_id
          AND contract.state = 'confirmed'
          AND contract.version = run.contract_version_bound
          AND contract.contract_hash = run.contract_hash_bound
        JOIN candidate_linux_post_exploit_specs spec
          ON spec.id = ?
          AND spec.status = 'active'
          AND spec.transport_type = 'candidate_runtime_session_v1'
          AND spec.transport_binding_id = ?
        JOIN script_artifacts candidate_script
          ON candidate_script.id = spec.script_artifact_id
          AND candidate_script.mission_id = action.mission_id
          AND candidate_script.run_id = action.run_id
          AND candidate_script.validation_state = 'approved'
        JOIN exploit_outcome_observer_specs candidate_observer
          ON candidate_observer.id =
            spec.exploit_outcome_observer_spec_id
          AND candidate_observer.script_artifact_id = candidate_script.id
          AND candidate_observer.script_content_hash =
            candidate_script.content_hash
          AND candidate_observer.status = 'active'
        WHERE action.action_type = ?
          AND action.action_class = ?
          AND action.status = 'running'
          AND action.scoped_target = ?
          AND json_extract(
            action.normalized_arguments_json,
            '$.sessionArtifactId'
          ) = ?
          AND json_extract(
            action.normalized_arguments_json,
            '$.postExploitSpecId'
          ) = spec.id
          AND EXISTS (
            SELECT 1 FROM json_each(
              json_extract(contract.action_policy_json, '$.allowedActionClasses')
            ) allowed WHERE allowed.value = action.action_class
          )
          AND EXISTS (
            SELECT 1
            FROM attack_attempts attempt
            JOIN plan_steps origin_step ON origin_step.id = attempt.step_id
              AND origin_step.plan_id = step.plan_id
              AND origin_step.ordinal < step.ordinal
            JOIN topology_nodes target ON target.id = attempt.target_asset_id
              AND target.scope_status = 'allowed'
              AND ? IN (target.normalized_identity, target.primary_label)
            JOIN attack_attempt_evidence link
              ON link.attack_attempt_id = attempt.id
              AND link.relationship = 'outcome'
            JOIN evidence proof ON proof.id = link.evidence_id
              AND proof.verification_state = 'verified'
              AND proof.evidence_type = 'exploit_validation_result'
              AND proof.mission_id = action.mission_id
              AND proof.run_id = action.run_id
            WHERE attempt.mission_id = action.mission_id
              AND attempt.run_id = action.run_id
              AND attempt.status = 'succeeded'
              AND attempt.action_class = 'exploit_validation'
              AND EXISTS (
                SELECT 1 FROM json_each(attempt.prerequisites_json)
                WHERE value = spec.script_artifact_id
              )
          )
        LIMIT 1
      `).get(
        request.postExploitSpecId,
        request.transportBindingId,
        actionType,
        actionClass,
        request.exactTarget,
        request.sessionArtifactId,
        request.exactTarget,
      ));
    }
    if (operation === "close") {
      return Boolean(this.options.database.prepare(`
        SELECT 1 AS present
        FROM session_artifacts session
        JOIN candidate_linux_post_exploit_specs spec
          ON spec.id = session.post_exploit_spec_id
          AND spec.status = 'active'
          AND spec.transport_type = 'candidate_runtime_session_v1'
          AND spec.transport_binding_id = ?
        JOIN script_artifacts candidate_script
          ON candidate_script.id = spec.script_artifact_id
          AND candidate_script.mission_id = session.mission_id
          AND candidate_script.run_id = session.run_id
          AND candidate_script.validation_state = 'approved'
        JOIN exploit_outcome_observer_specs candidate_observer
          ON candidate_observer.id =
            spec.exploit_outcome_observer_spec_id
          AND candidate_observer.script_artifact_id = candidate_script.id
          AND candidate_observer.script_content_hash =
            candidate_script.content_hash
          AND candidate_observer.status = 'active'
        JOIN attack_attempts attempt
          ON attempt.id = session.origin_attack_attempt_id
          AND attempt.status = 'succeeded'
        JOIN attack_attempt_evidence link
          ON link.attack_attempt_id = attempt.id
          AND link.evidence_id = session.exploit_outcome_evidence_id
          AND link.relationship = 'outcome'
        JOIN evidence proof ON proof.id = link.evidence_id
          AND proof.verification_state = 'verified'
          AND proof.evidence_type = 'exploit_validation_result'
        WHERE session.id = ?
          AND session.post_exploit_spec_id = ?
          AND session.exact_target = ?
          AND session.status IN (
            'reserved', 'opening', 'active', 'privileged', 'closing'
          )
        LIMIT 1
      `).get(
        request.transportBindingId,
        request.sessionArtifactId,
        request.postExploitSpecId,
        request.exactTarget,
      ));
    }
    const privilege = request as CandidateRuntimeLinuxPrivilegeRequest;
    const actionType = operation === "privilege_escalation"
      || operation === "observe_root_identity"
      ? AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE
      : operation === "prove_root_flag_hash"
        ? AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
        : AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE;
    const actionClass = operation === "privilege_escalation"
      || operation === "observe_root_identity"
      ? "privilege_escalation"
      : operation === "prove_root_flag_hash"
        ? "data_access_impact_validation"
        : "cleanup_restoration";
    const actionId = "actionId" in privilege
      ? privilege.actionId
      : null;
    return Boolean(this.options.database.prepare(`
      SELECT 1 AS present
      FROM session_artifacts session
      JOIN candidate_linux_post_exploit_specs spec
        ON spec.id = session.post_exploit_spec_id
        AND spec.status = 'active'
        AND spec.transport_type = 'candidate_runtime_session_v1'
        AND spec.transport_binding_id = ?
      JOIN script_artifacts candidate_script
        ON candidate_script.id = spec.script_artifact_id
        AND candidate_script.mission_id = session.mission_id
        AND candidate_script.run_id = session.run_id
        AND candidate_script.validation_state = 'approved'
      JOIN exploit_outcome_observer_specs candidate_observer
        ON candidate_observer.id = spec.exploit_outcome_observer_spec_id
        AND candidate_observer.script_artifact_id = candidate_script.id
        AND candidate_observer.script_content_hash =
          candidate_script.content_hash
        AND candidate_observer.status = 'active'
      JOIN attack_attempts attempt
        ON attempt.id = session.origin_attack_attempt_id
        AND attempt.status = 'succeeded'
      JOIN attack_attempt_evidence link
        ON link.attack_attempt_id = attempt.id
        AND link.evidence_id = session.exploit_outcome_evidence_id
        AND link.relationship = 'outcome'
      JOIN evidence proof ON proof.id = link.evidence_id
        AND proof.verification_state = 'verified'
        AND proof.evidence_type = 'exploit_validation_result'
      JOIN actions action
        ON action.mission_id = session.mission_id
        AND action.run_id = session.run_id
        AND action.action_type = ?
        AND action.action_class = ?
        AND action.status = 'running'
        AND action.scoped_target = session.exact_target
        AND json_extract(
          action.normalized_arguments_json,
          '$.sessionArtifactId'
        ) = session.id
      JOIN plan_steps step ON step.id = action.step_id
        AND step.plan_id = session.plan_id
      JOIN runs run ON run.id = session.run_id
        AND run.current_plan_id = step.plan_id
        AND run.journey = 'autonomous'
        AND run.control_plane = 'ti_scale'
      JOIN missions mission ON mission.id = session.mission_id
        AND mission.control_plane = 'ti_scale'
        AND mission.authorization_status = 'verified'
      JOIN mission_contracts contract ON contract.id = run.contract_id
        AND contract.id = action.contract_id
        AND contract.state = 'confirmed'
        AND contract.version = run.contract_version_bound
        AND contract.contract_hash = run.contract_hash_bound
      JOIN session_artifact_leases lease
        ON lease.session_artifact_id = session.id
        AND lease.fencing_token = ?
        AND lease.released_at IS NULL
        AND lease.expires_at > ?
      WHERE session.id = ?
        AND session.post_exploit_spec_id = ?
        AND session.exact_target = ?
        AND session.candidate_binding_hash = ?
        AND (? IS NULL OR action.id = ?)
        AND EXISTS (
          SELECT 1 FROM json_each(
            json_extract(contract.action_policy_json, '$.allowedActionClasses')
          ) allowed WHERE allowed.value = action.action_class
        )
      LIMIT 1
    `).get(
      privilege.transportBindingId,
      actionType,
      actionClass,
      privilege.leaseFencingToken,
      (this.options.now ?? (() => new Date()))().toISOString(),
      privilege.sessionArtifactId,
      privilege.postExploitSpecId,
      privilege.exactTarget,
      privilege.candidateBindingHash,
      actionId,
      actionId,
    ));
  }

  readiness(): CandidateLinuxTransportReadiness {
    const manifest = this.options.loadedManifest;
    const now = (this.options.now ?? (() => new Date()))();
    const databaseBindingsCurrent = this.databaseBindingsCurrent();
    const valid = databaseBindingsCurrent && this.attestation
      && Date.parse(this.attestation.expiresAt) > now.getTime();
    const reviewedRealTargetBindings =
      manifest.value.bindings.length > 0
      && manifest.value.bindings.every(
        (binding) =>
          binding.candidateClass === "reviewed_real_candidate_v1"
          && binding.realTargetSupport === true,
      );
    return Object.freeze({
      status: valid ? "ready" : "blocked",
      code: valid
        ? "candidate_linux_transport_ready"
        : "candidate_linux_transport_unavailable",
      reason: valid
        ? "The exact candidate Linux transport bindings are hash-pinned and currently attested."
        : !databaseBindingsCurrent
          ? "One or more transport bindings do not resolve to an active, hash-matched candidate post-exploit specification."
          : "The candidate Linux transport bindings have not completed a current broker attestation.",
      manifestSha256: manifest.receipt.sourceSha256,
      bindingIds: Object.freeze(
        manifest.value.bindings.map((binding) => binding.bindingId),
      ),
      bindingCapabilities: Object.freeze(
        manifest.value.bindings.map((binding) => Object.freeze({
          bindingId: binding.bindingId,
          candidateClass: binding.candidateClass,
          realTargetSupport: binding.realTargetSupport,
        })),
      ),
      readinessScope: reviewedRealTargetBindings
        ? "reviewed_real_candidate"
        : "production_path_proof_only",
      missionExecutionReady: Boolean(valid && reviewedRealTargetBindings),
      expiresAt: valid ? this.attestation!.expiresAt : null,
    });
  }

  /**
   * A current broker attestation proves that the typed transport boundary is
   * installed and can be exercised. It does not, by itself, authorize mission
   * execution. Disposable bindings deliberately remain visible as
   * production-path proofs while only an all-real-target, reviewed binding
   * set may be projected into mission planning or executable tool surfaces.
   */
  missionExecutionReady(): boolean {
    return this.readiness().missionExecutionReady;
  }

  authorize(
    request: CandidateLinuxTransportRequest,
  ): CandidateLinuxTransportOperation {
    const operation = assertTypedRequest(request);
    const binding = this.options.loadedManifest.value.bindings.find(
      (candidate) => candidate.bindingId === request.transportBindingId,
    );
    if (!binding
      || !this.acceptsPostExploitSpec(
        request.transportBindingId,
        request.postExploitSpecId,
      )
      || !binding.operations.includes(operation)) {
      throw new Error(
        "Candidate Linux transport binding does not match the reviewed spec",
      );
    }
    const spec = this.options.database.prepare(`
      SELECT id, spec_hash, transport_binding_id, transport_type, status
      FROM candidate_linux_post_exploit_specs WHERE id = ?
    `).get(request.postExploitSpecId) as {
      readonly id: string;
      readonly spec_hash: string;
      readonly transport_binding_id: string;
      readonly transport_type: string;
      readonly status: string;
    } | undefined;
    if (!spec || spec.status !== "active"
      || spec.transport_type !== "candidate_runtime_session_v1"
      || spec.transport_binding_id !== binding.bindingId
      || (
        request.postExploitSpecId === binding.postExploitSpecId
        && spec.spec_hash !== binding.postExploitSpecSha256
      )) {
      throw new Error("Candidate Linux transport binding is stale or inactive");
    }
    if (!this.canonicalRequestCurrent(request, operation)) {
      throw new Error(
        "Candidate Linux transport request does not match the current signed action, plan, succeeded AttackAttempt, session fence, and exact target",
      );
    }
    return operation;
  }

  async attest(signal: AbortSignal = new AbortController().signal):
  Promise<CandidateLinuxTransportAttestation> {
    assertPinnedBroker(this.options.loadedManifest.value);
    if (!this.databaseBindingsCurrent()) {
      throw new Error(
        "Candidate Linux transport attestation requires every binding to resolve to an active hash-matched candidate specification",
      );
    }
    const raw = plain(await unixRequest(
      this.options.loadedManifest.value.broker.socketPath,
      this.options.loadedManifest.value.broker.socketGid,
      Object.freeze({
        operation: "attest",
        protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
        manifestSha256: this.options.loadedManifest.receipt.sourceSha256,
      }),
      signal,
    ), "candidate transport attestation");
    exactKeys(raw, [
      "bindingCapabilities",
      "bindingIds",
      "boundary",
      "brokerExecutableSha256",
      "expiresAt",
      "grantsMissionExecution",
      "manifestSha256",
      "observedAt",
      "protocolVersion",
      "receiptSha256",
      "schemaVersion",
    ], "candidate transport attestation");
    const boundary = parseCandidateLinuxTransportBindingManifest({
      ...this.options.loadedManifest.value,
      boundary: raw.boundary,
    }).boundary;
    const observedAt = responseTimestamp(raw.observedAt, "observedAt");
    const expiresAt = responseTimestamp(raw.expiresAt, "expiresAt");
    const bindingIds = this.options.loadedManifest.value.bindings
      .map((binding) => binding.bindingId);
    const bindingCapabilities = this.options.loadedManifest.value.bindings
      .map((binding) => Object.freeze({
        bindingId: binding.bindingId,
        candidateClass: binding.candidateClass,
        realTargetSupport: binding.realTargetSupport,
      }));
    const now = (this.options.now ?? (() => new Date()))().getTime();
    const observedTime = Date.parse(observedAt);
    const expiresTime = Date.parse(expiresAt);
    if (raw.schemaVersion
      !== CANDIDATE_LINUX_TRANSPORT_ATTESTATION_SCHEMA_VERSION
      || raw.protocolVersion !== CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION
      || raw.manifestSha256 !== this.options.loadedManifest.receipt.sourceSha256
      || raw.brokerExecutableSha256
        !== this.options.loadedManifest.value.broker.executableSha256
      || raw.grantsMissionExecution !== false
      || !Array.isArray(raw.bindingIds)
      || raw.bindingIds.length !== bindingIds.length
      || raw.bindingIds.some((id, index) => id !== bindingIds[index])
      || !Array.isArray(raw.bindingCapabilities)
      || raw.bindingCapabilities.length !== bindingCapabilities.length
      || raw.bindingCapabilities.some((value, index) => {
        try {
          const capability = plain(value, "binding capability");
          exactKeys(capability, [
            "bindingId",
            "candidateClass",
            "realTargetSupport",
          ], "binding capability");
          const expected = bindingCapabilities[index];
          return !expected
            || capability.bindingId !== expected.bindingId
            || capability.candidateClass !== expected.candidateClass
            || capability.realTargetSupport !== expected.realTargetSupport;
        } catch {
          return true;
        }
      })
      || observedTime < now - 60_000
      || observedTime > now + 5_000
      || expiresTime <= now
      || expiresTime <= observedTime
      || expiresTime > observedTime + 5 * 60_000
      || typeof raw.receiptSha256 !== "string"
      || !SHA256.test(raw.receiptSha256)) {
      throw new Error("Candidate Linux transport attestation is invalid");
    }
    const unsigned = {
      schemaVersion: raw.schemaVersion,
      protocolVersion: raw.protocolVersion,
      manifestSha256: raw.manifestSha256,
      brokerExecutableSha256: raw.brokerExecutableSha256,
      bindingIds: raw.bindingIds,
      bindingCapabilities: raw.bindingCapabilities,
      boundary: raw.boundary,
      grantsMissionExecution: raw.grantsMissionExecution,
      observedAt,
      expiresAt,
    };
    if (digestCanonicalJson(unsigned, {
      maxBytes: 64 * 1024,
      maxDepth: 16,
    }).sha256 !== raw.receiptSha256) {
      throw new Error("Candidate Linux transport attestation hash is invalid");
    }
    this.attestation = Object.freeze({
      ...unsigned,
      schemaVersion: CANDIDATE_LINUX_TRANSPORT_ATTESTATION_SCHEMA_VERSION,
      protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
      manifestSha256: raw.manifestSha256 as string,
      brokerExecutableSha256: raw.brokerExecutableSha256 as string,
      bindingIds: Object.freeze([...(raw.bindingIds as string[])]),
      bindingCapabilities: Object.freeze(
        bindingCapabilities.map((capability) => Object.freeze({
          ...capability,
        })),
      ),
      boundary,
      grantsMissionExecution: false,
      receiptSha256: raw.receiptSha256,
    });
    return this.attestation;
  }

  async invoke(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown> {
    const readiness = this.readiness();
    if (readiness.status !== "ready") {
      throw new Error("Candidate Linux transport is not currently attested");
    }
    this.authorize(request);
    return await unixRequest(
      this.options.loadedManifest.value.broker.socketPath,
      this.options.loadedManifest.value.broker.socketGid,
      Object.freeze({
        protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
        bindingManifestSha256: this.options.loadedManifest.receipt.sourceSha256,
        request,
      }),
      signal,
    );
  }
}

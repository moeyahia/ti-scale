import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { isIP } from "node:net";
import { dirname, isAbsolute, resolve, sep } from "node:path";
import {
  digestCanonicalJson,
} from "../mcp";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";
import {
  LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
} from "./CandidateLinuxPrivilegeContinuation";
import type {
  CandidateLinuxTransportBindingHandler,
} from "./CandidateLinuxTransportBroker";
import type {
  CandidateLinuxTransportBindingManifest,
  CandidateLinuxTransportRequest,
} from "./CandidateLinuxTransportBindingRegistry";
import type { CandidateLinuxTargetScope } from "./CandidateLinuxTargetScope";

export const DISPOSABLE_LOCAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION =
  "ti-scale.disposable-local-candidate-linux-profile.v1" as const;

const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u;
const PRINCIPAL = /^[a-z_][a-z0-9_-]{0,63}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const USER_FLAG_PATH = /^\/home\/([a-z_][a-z0-9_-]{0,63})\/user\.txt$/u;
const MAXIMUM_PROOF_BYTES = 4_096;

export interface DisposableLocalCandidateLinuxProfile {
  readonly schemaVersion:
    typeof DISPOSABLE_LOCAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION;
  readonly profileId: string;
  readonly candidateClass: "disposable_local_fixture_v1";
  readonly disposableSimulationOnly: true;
  readonly realTargetSupport: false;
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly postExploitSpecSha256: string;
  readonly exactTarget: string;
  readonly identity: Readonly<{
    readonly principal: string;
    readonly uid: number;
    readonly gid: number;
    readonly groups: readonly string[];
  }>;
  readonly userProof: Readonly<{
    readonly declaredPath: string;
    readonly sourceFilePath: string;
    readonly expectedSha256: string;
  }>;
  readonly rootProof: Readonly<{
    readonly declaredPath: "/root/root.txt";
    readonly sourceFilePath: string;
    readonly expectedSha256: string;
  }>;
  readonly stateFilePath: string;
}

interface SessionState {
  readonly sessionArtifactId: string;
  readonly exactTarget: string;
  readonly stage: "open" | "privileged" | "closed";
  readonly leaseFencingToken?: number;
  readonly privilegeActionId?: string;
}

interface StateDocument {
  readonly schemaVersion: "ti-scale.disposable-local-candidate-state.v1";
  readonly sessions: readonly SessionState[];
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
    || /[\u0000-\u001F\u007F]/u.test(value)
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

export function parseDisposableLocalCandidateLinuxProfile(
  input: unknown,
): DisposableLocalCandidateLinuxProfile {
  const root = plain(input, "disposable candidate profile");
  exactKeys(root, [
    "bindingId",
    "candidateClass",
    "disposableSimulationOnly",
    "exactTarget",
    "identity",
    "postExploitSpecId",
    "postExploitSpecSha256",
    "profileId",
    "realTargetSupport",
    "rootProof",
    "schemaVersion",
    "stateFilePath",
    "userProof",
  ], "disposable candidate profile");
  if (
    root.schemaVersion
      !== DISPOSABLE_LOCAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION
    || root.candidateClass !== "disposable_local_fixture_v1"
    || root.disposableSimulationOnly !== true
    || root.realTargetSupport !== false
  ) {
    throw new TypeError(
      "The profile must be an explicitly disposable local simulation",
    );
  }
  if (
    typeof root.exactTarget !== "string"
    || isIP(root.exactTarget) === 0
    || !["127.0.0.1", "127.0.0.2", "::1"].includes(root.exactTarget)
  ) {
    throw new TypeError(
      "The disposable candidate target must be one reviewed loopback IP",
    );
  }
  const identity = plain(root.identity, "identity");
  exactKeys(identity, ["gid", "groups", "principal", "uid"], "identity");
  if (
    typeof identity.principal !== "string"
    || !PRINCIPAL.test(identity.principal)
    || !Number.isSafeInteger(identity.uid)
    || Number(identity.uid) < 1
    || !Number.isSafeInteger(identity.gid)
    || Number(identity.gid) < 1
    || !Array.isArray(identity.groups)
    || identity.groups.length < 1
    || identity.groups.length > 32
    || identity.groups.some(
      (group) => typeof group !== "string" || !PRINCIPAL.test(group),
    )
    || new Set(identity.groups).size !== identity.groups.length
  ) {
    throw new TypeError("The disposable candidate identity is invalid");
  }
  const userProof = plain(root.userProof, "userProof");
  exactKeys(
    userProof,
    ["declaredPath", "expectedSha256", "sourceFilePath"],
    "userProof",
  );
  if (
    typeof userProof.declaredPath !== "string"
    || !USER_FLAG_PATH.test(userProof.declaredPath)
    || USER_FLAG_PATH.exec(userProof.declaredPath)?.[1] !== identity.principal
  ) {
    throw new TypeError(
      "The user proof path must match the disposable principal",
    );
  }
  const rootProof = plain(root.rootProof, "rootProof");
  exactKeys(
    rootProof,
    ["declaredPath", "expectedSha256", "sourceFilePath"],
    "rootProof",
  );
  if (rootProof.declaredPath !== "/root/root.txt") {
    throw new TypeError("The root proof path must be exactly /root/root.txt");
  }
  return Object.freeze({
    schemaVersion: DISPOSABLE_LOCAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
    profileId: stableId(root.profileId, "profileId"),
    candidateClass: "disposable_local_fixture_v1",
    disposableSimulationOnly: true,
    realTargetSupport: false,
    bindingId: stableId(root.bindingId, "bindingId"),
    postExploitSpecId: stableId(root.postExploitSpecId, "postExploitSpecId"),
    postExploitSpecSha256: sha256(
      root.postExploitSpecSha256,
      "postExploitSpecSha256",
    ),
    exactTarget: root.exactTarget,
    identity: Object.freeze({
      principal: identity.principal,
      uid: nonNegativeInteger(identity.uid, "identity.uid"),
      gid: nonNegativeInteger(identity.gid, "identity.gid"),
      groups: Object.freeze([...(identity.groups as string[])]),
    }),
    userProof: Object.freeze({
      declaredPath: userProof.declaredPath,
      sourceFilePath: absolutePath(
        userProof.sourceFilePath,
        "userProof.sourceFilePath",
      ),
      expectedSha256: sha256(
        userProof.expectedSha256,
        "userProof.expectedSha256",
      ),
    }),
    rootProof: Object.freeze({
      declaredPath: "/root/root.txt",
      sourceFilePath: absolutePath(
        rootProof.sourceFilePath,
        "rootProof.sourceFilePath",
      ),
      expectedSha256: sha256(
        rootProof.expectedSha256,
        "rootProof.expectedSha256",
      ),
    }),
    stateFilePath: absolutePath(root.stateFilePath, "stateFilePath"),
  });
}

export function loadTrustedDisposableLocalCandidateLinuxProfile(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<DisposableLocalCandidateLinuxProfile> {
  return loadTrustedJson(
    { ...reference, maximumBytes: reference.maximumBytes ?? 32 * 1_024 },
    parseDisposableLocalCandidateLinuxProfile,
  );
}

function hashBytes(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function proofFile(
  path: string,
  expectedSha256: string,
  allowedOwnerUids: readonly number[],
): Readonly<{ sha256: string; byteSize: number }> {
  const metadata = lstatSync(path);
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || !allowedOwnerUids.includes(metadata.uid)
    || (metadata.mode & 0o022) !== 0
    || metadata.size < 1
    || metadata.size > MAXIMUM_PROOF_BYTES
  ) {
    throw new Error(
      "The disposable proof source is not an owner-controlled bounded file",
    );
  }
  const bytes = readFileSync(path);
  const digest = hashBytes(bytes);
  if (digest !== expectedSha256) {
    throw new Error("The disposable proof source failed its pinned hash");
  }
  return Object.freeze({ sha256: digest, byteSize: bytes.byteLength });
}

function parseState(value: unknown): StateDocument {
  const state = plain(value, "disposable candidate state");
  exactKeys(state, ["schemaVersion", "sessions"], "disposable candidate state");
  if (
    state.schemaVersion !== "ti-scale.disposable-local-candidate-state.v1"
    || !Array.isArray(state.sessions)
    || state.sessions.length > 1_024
  ) {
    throw new TypeError("The disposable candidate state is invalid");
  }
  const sessions = state.sessions.map((candidate, index) => {
    const session = plain(candidate, `sessions[${index}]`);
    const privileged = session.stage === "privileged";
    exactKeys(
      session,
      privileged
        ? [
            "exactTarget",
            "leaseFencingToken",
            "privilegeActionId",
            "sessionArtifactId",
            "stage",
          ]
        : ["exactTarget", "sessionArtifactId", "stage"],
      `sessions[${index}]`,
    );
    if (!["open", "privileged", "closed"].includes(String(session.stage))) {
      throw new TypeError(`sessions[${index}].stage is invalid`);
    }
    const normalized: SessionState = {
      sessionArtifactId: stableId(
        session.sessionArtifactId,
        `sessions[${index}].sessionArtifactId`,
      ),
      exactTarget: String(session.exactTarget),
      stage: session.stage as SessionState["stage"],
      ...(privileged
        ? {
            leaseFencingToken: nonNegativeInteger(
              session.leaseFencingToken,
              `sessions[${index}].leaseFencingToken`,
            ),
            privilegeActionId: stableId(
              session.privilegeActionId,
              `sessions[${index}].privilegeActionId`,
            ),
          }
        : {}),
    };
    return Object.freeze(normalized);
  });
  return Object.freeze({
    schemaVersion: "ti-scale.disposable-local-candidate-state.v1",
    sessions: Object.freeze(sessions),
  });
}

function receipt<T extends Record<string, unknown>>(
  material: T,
  field: string,
): Readonly<T & Record<string, string>> {
  return Object.freeze({
    ...material,
    [field]: digestCanonicalJson(
      material,
      { maxBytes: 32 * 1_024, maxDepth: 12 },
    ).sha256,
  });
}

export class DisposableLocalCandidateLinuxTransportHandler
implements CandidateLinuxTransportBindingHandler {
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly candidateClass = "disposable_local_fixture_v1" as const;
  readonly handlerProfileSha256: string;
  readonly realTargetSupport = false as const;
  readonly targetScope: CandidateLinuxTargetScope;
  private readonly sessions = new Map<string, SessionState>();

  constructor(private readonly options: Readonly<{
    loadedProfile: LoadedTrustedJson<DisposableLocalCandidateLinuxProfile>;
    binding: CandidateLinuxTransportBindingManifest["bindings"][number];
    allowedProofFileOwnerUids?: readonly number[];
    now?: () => Date;
  }>) {
    const profile = options.loadedProfile.value;
    if (
      options.loadedProfile.receipt.sourceSha256
        !== options.binding.handlerProfileSha256
      || profile.bindingId !== options.binding.bindingId
      || profile.postExploitSpecId !== options.binding.postExploitSpecId
      || profile.postExploitSpecSha256
        !== options.binding.postExploitSpecSha256
      || profile.candidateClass !== options.binding.candidateClass
      || profile.realTargetSupport !== options.binding.realTargetSupport
      || resolve(options.loadedProfile.receipt.sourcePath)
        !== options.binding.handlerProfilePath
    ) {
      throw new Error(
        "The disposable handler profile does not match the pinned binding",
      );
    }
    this.bindingId = profile.bindingId;
    this.postExploitSpecId = profile.postExploitSpecId;
    this.handlerProfileSha256 = options.loadedProfile.receipt.sourceSha256;
    this.targetScope = options.binding.targetScope;
    this.restoreState();
    this.verifyProofSources();
  }

  private proofOwners(): readonly number[] {
    return this.options.allowedProofFileOwnerUids ?? Object.freeze([0]);
  }

  private verifyProofSources(): void {
    const profile = this.options.loadedProfile.value;
    proofFile(
      profile.userProof.sourceFilePath,
      profile.userProof.expectedSha256,
      this.proofOwners(),
    );
    proofFile(
      profile.rootProof.sourceFilePath,
      profile.rootProof.expectedSha256,
      this.proofOwners(),
    );
  }

  private restoreState(): void {
    const path = this.options.loadedProfile.value.stateFilePath;
    if (!existsSync(path)) return;
    const metadata = lstatSync(path);
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || (metadata.mode & 0o077) !== 0
      || metadata.size > 256 * 1_024
    ) {
      throw new Error("The disposable candidate state file is unsafe");
    }
    const state = parseState(
      JSON.parse(readFileSync(path, "utf8")) as unknown,
    );
    for (const session of state.sessions) {
      if (session.exactTarget
        !== this.options.loadedProfile.value.exactTarget) {
        throw new Error("The disposable candidate state target is stale");
      }
      this.sessions.set(session.sessionArtifactId, session);
    }
  }

  private persistState(): void {
    const path = this.options.loadedProfile.value.stateFilePath;
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const state: StateDocument = {
      schemaVersion: "ti-scale.disposable-local-candidate-state.v1",
      sessions: Object.freeze(
        [...this.sessions.values()].sort((left, right) =>
          left.sessionArtifactId.localeCompare(right.sessionArtifactId)),
      ),
    };
    const temporary = `${path}.tmp-${process.pid}`;
    writeFileSync(temporary, `${JSON.stringify(state)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    renameSync(temporary, path);
  }

  private session(
    request: CandidateLinuxTransportRequest,
    allowed: readonly SessionState["stage"][],
  ): SessionState {
    const state = this.sessions.get(request.sessionArtifactId);
    if (
      !state
      || state.exactTarget !== request.exactTarget
      || !allowed.includes(state.stage)
    ) {
      throw new Error(
        "The disposable candidate session is not in the required state",
      );
    }
    return state;
  }

  private assertRequestIdentity(
    request: CandidateLinuxTransportRequest,
  ): void {
    const profile = this.options.loadedProfile.value;
    if (
      request.transportBindingId !== profile.bindingId
      || request.postExploitSpecId !== profile.postExploitSpecId
      || request.exactTarget !== profile.exactTarget
    ) {
      throw new Error(
        "The request does not match the disposable candidate identity",
      );
    }
  }

  async handle(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown> {
    if (signal.aborted) throw new Error("Disposable candidate request cancelled");
    this.assertRequestIdentity(request);
    const profile = this.options.loadedProfile.value;
    const now = (this.options.now ?? (() => new Date()))().toISOString();
    switch (request.operation) {
      case "open": {
        const existing = this.sessions.get(request.sessionArtifactId);
        if (existing && existing.stage === "closed") {
          throw new Error("The disposable candidate session is already closed");
        }
        if (!existing) {
          this.sessions.set(request.sessionArtifactId, Object.freeze({
            sessionArtifactId: request.sessionArtifactId,
            exactTarget: request.exactTarget,
            stage: "open",
          }));
          this.persistState();
        }
        return Object.freeze({
          accepted: true,
          sessionArtifactId: request.sessionArtifactId,
        });
      }
      case "observe_identity":
        this.session(request, ["open"]);
        return Object.freeze({
          sessionArtifactId: request.sessionArtifactId,
          principal: profile.identity.principal,
          uid: profile.identity.uid,
          gid: profile.identity.gid,
          groups: profile.identity.groups,
        });
      case "prove_user_flag_hash": {
        this.session(request, ["open"]);
        if (request.declaredPath !== profile.userProof.declaredPath) {
          throw new Error("The user proof path is not the pinned fixture path");
        }
        const proof = proofFile(
          profile.userProof.sourceFilePath,
          profile.userProof.expectedSha256,
          this.proofOwners(),
        );
        return Object.freeze({
          sessionArtifactId: request.sessionArtifactId,
          declaredPath: profile.userProof.declaredPath,
          sha256: proof.sha256,
          byteSize: proof.byteSize,
        });
      }
      case "close": {
        const current = this.session(request, ["open"]);
        this.sessions.set(current.sessionArtifactId, Object.freeze({
          sessionArtifactId: current.sessionArtifactId,
          exactTarget: current.exactTarget,
          stage: "closed",
        }));
        this.persistState();
        return Object.freeze({
          closed: true,
          sessionArtifactId: request.sessionArtifactId,
        });
      }
      case "privilege_escalation": {
        const current = this.session(request, ["open", "privileged"]);
        if (
          current.stage === "privileged"
          && (
            current.leaseFencingToken !== request.leaseFencingToken
            || current.privilegeActionId !== request.actionId
          )
        ) {
          throw new Error(
            "The disposable privilege operation conflicts with its fence",
          );
        }
        this.sessions.set(current.sessionArtifactId, Object.freeze({
          sessionArtifactId: current.sessionArtifactId,
          exactTarget: current.exactTarget,
          stage: "privileged",
          leaseFencingToken: request.leaseFencingToken,
          privilegeActionId: request.actionId,
        }));
        this.persistState();
        return receipt({
          schemaVersion: LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
          sessionArtifactId: request.sessionArtifactId,
          accepted: true as const,
          observedAt: now,
        }, "receiptSha256");
      }
      case "observe_root_identity": {
        const current = this.session(request, ["privileged"]);
        if (
          current.leaseFencingToken !== request.leaseFencingToken
          || current.privilegeActionId !== request.actionId
        ) {
          throw new Error("The root identity request failed its session fence");
        }
        return receipt({
          schemaVersion: LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
          sessionArtifactId: request.sessionArtifactId,
          principal: "root" as const,
          uid: 0 as const,
          gid: 0 as const,
          groups: Object.freeze(["root"]),
          observedAt: now,
        }, "observationSha256");
      }
      case "prove_root_flag_hash": {
        const current = this.session(request, ["privileged"]);
        if (
          current.leaseFencingToken !== request.leaseFencingToken
          || current.privilegeActionId !== request.actionId
          || request.declaredPath !== profile.rootProof.declaredPath
        ) {
          throw new Error("The root proof request failed its pinned boundary");
        }
        const proof = proofFile(
          profile.rootProof.sourceFilePath,
          profile.rootProof.expectedSha256,
          this.proofOwners(),
        );
        return receipt({
          schemaVersion: LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
          sessionArtifactId: request.sessionArtifactId,
          declaredPath: "/root/root.txt" as const,
          contentSha256: proof.sha256,
          byteSize: proof.byteSize,
          observedAt: now,
        }, "proofSha256");
      }
      case "cleanup": {
        const current = this.session(request, ["privileged", "closed"]);
        if (
          current.stage === "privileged"
          && current.leaseFencingToken !== request.leaseFencingToken
        ) {
          throw new Error("The cleanup request failed its session fence");
        }
        this.sessions.set(current.sessionArtifactId, Object.freeze({
          sessionArtifactId: current.sessionArtifactId,
          exactTarget: current.exactTarget,
          stage: "closed",
        }));
        this.persistState();
        return receipt({
          schemaVersion: LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
          sessionArtifactId: request.sessionArtifactId,
          closed: true as const,
          observedAt: now,
        }, "receiptSha256");
      }
    }
  }
}

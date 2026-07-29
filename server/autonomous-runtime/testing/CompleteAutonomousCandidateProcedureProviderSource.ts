import { createHash } from "node:crypto";

export const COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID =
  "reviewed-complete-autonomous-fixture-v1" as const;
export const COMPLETE_AUTONOMOUS_SOURCE_POST_EXPLOIT_SPEC_ID =
  "post-exploit-spec:reviewed-complete-autonomous-fixture-v1" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_PROCEDURE_PROTOCOL_VERSION =
  "ti-scale.reviewed-real-candidate-linux-procedure.v1" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_PROCEDURE_PATH =
  "/usr/local/libexec/ti-scale/reviewed-real-candidate-linux-procedure" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_ADAPTER_PATH =
  "/usr/local/libexec/ti-scale/reviewed-real-candidate-linux-adapter" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET =
  "127.0.0.2:8080" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_GENERAL_EXTERNAL_TARGET_SUPPORT =
  false as const;

export interface CompleteAutonomousCandidateProcedureSourceInput {
  readonly scriptArtifactId: string;
  readonly exploitOutcomeObserverSpecId: string;
}

const SHA256 = /^[a-f0-9]{64}$/u;
const STABLE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;

function stableId(value: string, label: string): string {
  if (!STABLE_ID.test(value)) {
    throw new TypeError(`${label} must be a stable identifier`);
  }
  return value;
}

/**
 * Renders the complete-autonomous fixture's separately reviewed provider.
 *
 * The resulting executable is intentionally self-contained and has no generic
 * command, shell, argv, payload, credential, host, port, or path inputs. The
 * only network destinations encoded in its source are the eight typed fixture
 * operations on 127.0.0.2:8080.
 */
export function renderCompleteAutonomousCandidateProcedureProvider(
  input: CompleteAutonomousCandidateProcedureSourceInput,
): string {
  const identity = Object.freeze({
    bindingId: COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
    postExploitSpecId: COMPLETE_AUTONOMOUS_SOURCE_POST_EXPLOIT_SPEC_ID,
    scriptArtifactId: stableId(input.scriptArtifactId, "scriptArtifactId"),
    exploitOutcomeObserverSpecId: stableId(
      input.exploitOutcomeObserverSpecId,
      "exploitOutcomeObserverSpecId",
    ),
  });
  const embeddedIdentity = JSON.stringify(identity);
  return `#!/usr/bin/node
"use strict";
const crypto = require("node:crypto");
const http = require("node:http");

const IDENTITY = Object.freeze(${embeddedIdentity});
const PROTOCOL = ${JSON.stringify(COMPLETE_AUTONOMOUS_CANDIDATE_PROCEDURE_PROTOCOL_VERSION)};
const HOST = "127.0.0.2";
const PORT = 8080;
const SUPPORTED_TARGET = ${JSON.stringify(COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET)};
const GENERAL_EXTERNAL_TARGET_SUPPORT = false;
const TARGET_SCOPE = Object.freeze({
  schemaVersion: "ti-scale.candidate-linux-target-scope.v1",
  kind: "exact_target",
  exactTarget: HOST,
  endpoint: Object.freeze({ transport: "tcp", port: PORT }),
  generalMissionReadinessEligible: false,
});
const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const CONTROL = /[\\u0000-\\u001f\\u007f]/u;
const OPERATIONS = Object.freeze([
  "open",
  "observe_identity",
  "prove_user_flag_hash",
  "close",
  "privilege_escalation",
  "observe_root_identity",
  "prove_root_flag_hash",
  "cleanup",
]);
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

function plain(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(label + " must be a plain object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(label + " must be a plain object");
  }
  return value;
}

function exactKeys(value, keys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    throw new TypeError(label + " contains an unreviewed field");
  }
}

function stableId(value, label) {
  if (typeof value !== "string" || !ID.test(value)) {
    throw new TypeError(label + " must be a stable identifier");
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(label + " must be a lowercase SHA-256");
  }
  return value;
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.keys(value).sort().map(
    (key) => JSON.stringify(key) + ":" + canonical(value[key]),
  ).join(",") + "}";
}

function digest(value) {
  return crypto.createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

function withReceipt(value) {
  return Object.freeze({ ...value, receiptSha256: digest(value) });
}

function assertOuterIdentity(envelope, includeRequest) {
  exactKeys(envelope, includeRequest
    ? [
      "bindingId",
      "exploitOutcomeObserverSpecId",
      "operation",
      "postExploitSpecId",
      "procedureExecutableSha256",
      "profileSha256",
      "protocolVersion",
      "request",
      "scriptArtifactId",
      "targetScope",
    ]
    : [
      "bindingId",
      "exploitOutcomeObserverSpecId",
      "operation",
      "postExploitSpecId",
      "procedureExecutableSha256",
      "profileSha256",
      "protocolVersion",
      "scriptArtifactId",
      "targetScope",
    ],
  "provider envelope");
  if (
    envelope.protocolVersion !== PROTOCOL
    || envelope.bindingId !== IDENTITY.bindingId
    || envelope.postExploitSpecId !== IDENTITY.postExploitSpecId
    || envelope.scriptArtifactId !== IDENTITY.scriptArtifactId
    || envelope.exploitOutcomeObserverSpecId
      !== IDENTITY.exploitOutcomeObserverSpecId
    || canonical(envelope.targetScope) !== canonical(TARGET_SCOPE)
  ) {
    throw new Error("provider envelope identity does not match the reviewed fixture");
  }
  hash(envelope.profileSha256, "profileSha256");
  hash(envelope.procedureExecutableSha256, "procedureExecutableSha256");
}

function attestation(envelope) {
  const observedAt = new Date();
  const unsigned = Object.freeze({
    schemaVersion: "ti-scale.reviewed-real-candidate-linux-procedure-attestation.v1",
    protocolVersion: PROTOCOL,
    profileSha256: envelope.profileSha256,
    procedureExecutableSha256: envelope.procedureExecutableSha256,
    ...IDENTITY,
    candidateClass: "reviewed_real_candidate_v1",
    // Protocol-v1 discriminator only. Product readiness is separately scoped
    // to SUPPORTED_TARGET and explicitly denies general external-target use.
    realTargetSupport: true,
    targetScope: TARGET_SCOPE,
    operations: OPERATIONS,
    boundary: BOUNDARY,
    observedAt: observedAt.toISOString(),
    expiresAt: new Date(observedAt.getTime() + 60_000).toISOString(),
  });
  return withReceipt(unsigned);
}

function conformance(envelope) {
  const unsigned = Object.freeze({
    schemaVersion: "ti-scale.reviewed-real-candidate-linux-procedure-conformance.v1",
    protocolVersion: PROTOCOL,
    profileSha256: envelope.profileSha256,
    procedureExecutableSha256: envelope.procedureExecutableSha256,
    ...IDENTITY,
    targetScope: TARGET_SCOPE,
    cases: Object.freeze([
      { operation: "open", result: { accepted: true } },
      {
        operation: "observe_identity",
        result: { principal: "fixtureuser", uid: 1000, gid: 1000, groups: ["fixtureuser"] },
      },
      {
        operation: "prove_user_flag_hash",
        result: {
          sha256: "84126d0dd850199be29021aadbaee68cb9199047b1cb7ec9894ddb1e3562783c",
          byteSize: 32,
        },
      },
      { operation: "close", result: { closed: true } },
      { operation: "privilege_escalation", result: { accepted: true } },
      {
        operation: "observe_root_identity",
        result: { principal: "root", uid: 0, gid: 0, groups: ["root"] },
      },
      {
        operation: "prove_root_flag_hash",
        result: {
          sha256: "16b72cfab7dbca73cb348f4e59a74b5c56d6e95574c1e9ca84850d69f5fa9430",
          byteSize: 32,
        },
      },
      { operation: "cleanup", result: { closed: true } },
    ]),
  });
  return withReceipt(unsigned);
}

function commonRequest(request, operation) {
  if (
    SUPPORTED_TARGET !== HOST + ":" + String(PORT)
    || GENERAL_EXTERNAL_TARGET_SUPPORT !== false
    || request.operation !== operation
    || request.exactTarget !== HOST
    || request.transportBindingId !== IDENTITY.bindingId
  ) {
    throw new Error("typed request is outside the exact reviewed fixture binding");
  }
  stableId(request.postExploitSpecId, "request.postExploitSpecId");
  stableId(request.sessionArtifactId, "request.sessionArtifactId");
}

function privilegeFields(request) {
  stableId(request.actionId, "request.actionId");
  hash(request.candidateBindingHash, "request.candidateBindingHash");
  if (!Number.isSafeInteger(request.leaseFencingToken) || request.leaseFencingToken < 1) {
    throw new TypeError("request.leaseFencingToken must be a positive integer");
  }
}

function parseResponse(value, expectedKeys, label) {
  const result = plain(value, label);
  exactKeys(result, expectedKeys, label);
  if (result.fixtureOnly !== true) {
    throw new Error(label + " is not the reviewed fixture response");
  }
  return result;
}

function requestTarget(method, path, body, actionId) {
  return new Promise((resolve, reject) => {
    if (
      typeof path !== "string"
      || !path.startsWith("/ti-scale/session/")
      || CONTROL.test(path)
    ) {
      reject(new Error("fixed fixture endpoint invariant failed"));
      return;
    }
    const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const headers = {
      accept: "application/json",
      ...(encoded ? {
        "content-type": "application/json",
        "content-length": String(encoded.byteLength),
      } : {}),
      ...(actionId ? { "x-ti-scale-action": actionId } : {}),
    };
    const request = http.request({
      host: HOST,
      port: PORT,
      method,
      path,
      headers,
      agent: false,
      timeout: 3000,
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > 16 * 1024) {
          request.destroy(new Error("fixture response exceeded 16 KiB"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (response.statusCode !== 200) {
          reject(new Error("fixture endpoint rejected the typed operation"));
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch {
          reject(new Error("fixture endpoint returned invalid JSON"));
        }
      });
    });
    request.on("timeout", () => request.destroy(new Error("fixture endpoint timed out")));
    request.on("error", reject);
    if (encoded) request.end(encoded);
    else request.end();
  });
}

async function invoke(raw) {
  const request = plain(raw, "typed invoke request");
  const common = [
    "exactTarget",
    "operation",
    "postExploitSpecId",
    "sessionArtifactId",
    "transportBindingId",
  ];
  switch (request.operation) {
    case "open": {
      exactKeys(request, common, "open request");
      commonRequest(request, "open");
      const response = parseResponse(
        await requestTarget("POST", "/ti-scale/session/open", {
          exactTarget: HOST,
          sessionArtifactId: request.sessionArtifactId,
        }),
        ["accepted", "fixtureOnly", "schemaVersion", "sessionArtifactId"],
        "open response",
      );
      if (response.accepted !== true || response.sessionArtifactId !== request.sessionArtifactId) {
        throw new Error("fixture open response identity mismatch");
      }
      return { accepted: true };
    }
    case "observe_identity": {
      exactKeys(request, common, "observe identity request");
      commonRequest(request, "observe_identity");
      const query = new URLSearchParams({
        exactTarget: HOST,
        sessionArtifactId: request.sessionArtifactId,
      });
      const response = parseResponse(
        await requestTarget("GET", "/ti-scale/session/identity?" + query.toString()),
        ["fixtureOnly", "gid", "groups", "principal", "schemaVersion", "sessionArtifactId", "uid"],
        "identity response",
      );
      if (
        response.sessionArtifactId !== request.sessionArtifactId
        || response.principal !== "fixtureuser"
        || response.uid !== 1000
        || response.gid !== 1000
        || JSON.stringify(response.groups) !== JSON.stringify(["fixtureuser"])
      ) throw new Error("fixture identity response mismatch");
      return { principal: "fixtureuser", uid: 1000, gid: 1000, groups: ["fixtureuser"] };
    }
    case "prove_user_flag_hash": {
      exactKeys(request, [...common, "declaredPath"], "user proof request");
      commonRequest(request, "prove_user_flag_hash");
      if (request.declaredPath !== "/home/fixtureuser/user.txt") {
        throw new Error("user proof path is not profile-pinned");
      }
      const response = parseResponse(
        await requestTarget("POST", "/ti-scale/session/user-flag-proof", {
          exactTarget: HOST,
          sessionArtifactId: request.sessionArtifactId,
          declaredPath: "/home/fixtureuser/user.txt",
          returnContent: false,
        }),
        [
          "byteSize",
          "contentReturned",
          "declaredPath",
          "fixtureOnly",
          "schemaVersion",
          "sessionArtifactId",
          "sha256",
        ],
        "user proof response",
      );
      if (
        response.sessionArtifactId !== request.sessionArtifactId
        || response.declaredPath !== "/home/fixtureuser/user.txt"
        || response.contentReturned !== false
        || !SHA256.test(response.sha256)
        || !Number.isSafeInteger(response.byteSize)
        || response.byteSize < 1
        || response.byteSize > 4096
      ) throw new Error("fixture user proof response mismatch");
      return { sha256: response.sha256, byteSize: response.byteSize };
    }
    case "close": {
      exactKeys(request, common, "close request");
      commonRequest(request, "close");
      const response = parseResponse(
        await requestTarget("POST", "/ti-scale/session/cleanup", {
          sessionArtifactId: request.sessionArtifactId,
          operation: "cleanup",
          reason: "typed_close",
        }),
        ["closed", "fixtureOnly", "observedAt", "receiptSha256", "schemaVersion", "sessionArtifactId"],
        "close response",
      );
      if (response.closed !== true || response.sessionArtifactId !== request.sessionArtifactId) {
        throw new Error("fixture close response mismatch");
      }
      return { closed: true };
    }
    case "privilege_escalation": {
      exactKeys(
        request,
        [...common, "actionId", "candidateBindingHash", "leaseFencingToken"],
        "privilege request",
      );
      commonRequest(request, "privilege_escalation");
      privilegeFields(request);
      const response = parseResponse(
        await requestTarget("POST", "/ti-scale/session/privilege-escalation", {
          sessionArtifactId: request.sessionArtifactId,
          operation: "privilege_escalation",
        }, request.actionId),
        ["accepted", "fixtureOnly", "observedAt", "receiptSha256", "schemaVersion", "sessionArtifactId"],
        "privilege response",
      );
      if (response.accepted !== true || response.sessionArtifactId !== request.sessionArtifactId) {
        throw new Error("fixture privilege response mismatch");
      }
      return { accepted: true };
    }
    case "observe_root_identity": {
      exactKeys(
        request,
        [...common, "actionId", "candidateBindingHash", "leaseFencingToken"],
        "root identity request",
      );
      commonRequest(request, "observe_root_identity");
      privilegeFields(request);
      const query = new URLSearchParams({ sessionArtifactId: request.sessionArtifactId });
      const response = parseResponse(
        await requestTarget(
          "GET",
          "/ti-scale/session/root-identity?" + query.toString(),
          undefined,
          request.actionId,
        ),
        [
          "fixtureOnly",
          "gid",
          "groups",
          "observationSha256",
          "observedAt",
          "principal",
          "schemaVersion",
          "sessionArtifactId",
          "uid",
        ],
        "root identity response",
      );
      if (
        response.sessionArtifactId !== request.sessionArtifactId
        || response.principal !== "root"
        || response.uid !== 0
        || response.gid !== 0
        || !Array.isArray(response.groups)
        || !response.groups.includes("root")
      ) throw new Error("fixture root identity response mismatch");
      return { principal: "root", uid: 0, gid: 0, groups: ["root"] };
    }
    case "prove_root_flag_hash": {
      exactKeys(
        request,
        [
          ...common,
          "actionId",
          "candidateBindingHash",
          "declaredPath",
          "leaseFencingToken",
        ],
        "root proof request",
      );
      commonRequest(request, "prove_root_flag_hash");
      privilegeFields(request);
      if (request.declaredPath !== "/root/root.txt") {
        throw new Error("root proof path is not profile-pinned");
      }
      const response = parseResponse(
        await requestTarget("POST", "/ti-scale/session/root-flag-proof", {
          sessionArtifactId: request.sessionArtifactId,
          operation: "root_flag_hash_proof",
          declaredPath: "/root/root.txt",
          returnContent: false,
        }, request.actionId),
        [
          "byteSize",
          "contentReturned",
          "declaredPath",
          "fixtureOnly",
          "observedAt",
          "proofSha256",
          "schemaVersion",
          "sessionArtifactId",
          "contentSha256",
        ],
        "root proof response",
      );
      if (
        response.sessionArtifactId !== request.sessionArtifactId
        || response.declaredPath !== "/root/root.txt"
        || response.contentReturned !== false
        || !SHA256.test(response.contentSha256)
        || !Number.isSafeInteger(response.byteSize)
        || response.byteSize < 1
        || response.byteSize > 4096
      ) throw new Error("fixture root proof response mismatch");
      return { sha256: response.contentSha256, byteSize: response.byteSize };
    }
    case "cleanup": {
      exactKeys(
        request,
        [...common, "candidateBindingHash", "leaseFencingToken", "reason"],
        "cleanup request",
      );
      commonRequest(request, "cleanup");
      hash(request.candidateBindingHash, "request.candidateBindingHash");
      if (
        !Number.isSafeInteger(request.leaseFencingToken)
        || request.leaseFencingToken < 1
        || typeof request.reason !== "string"
        || !request.reason.trim()
        || request.reason.length > 256
        || CONTROL.test(request.reason)
      ) throw new TypeError("cleanup request fields are invalid");
      const response = parseResponse(
        await requestTarget("POST", "/ti-scale/session/cleanup", {
          sessionArtifactId: request.sessionArtifactId,
          operation: "cleanup",
          reason: request.reason,
        }),
        ["closed", "fixtureOnly", "observedAt", "receiptSha256", "schemaVersion", "sessionArtifactId"],
        "cleanup response",
      );
      if (response.closed !== true || response.sessionArtifactId !== request.sessionArtifactId) {
        throw new Error("fixture cleanup response mismatch");
      }
      return { closed: true };
    }
    default:
      throw new Error("unreviewed typed operation");
  }
}

async function main() {
  const raw = require("node:fs").readFileSync(0, "utf8");
  if (!raw.endsWith("\\n") || raw.indexOf("\\n") !== raw.length - 1 || Buffer.byteLength(raw) > 64 * 1024) {
    throw new Error("provider input must be exactly one bounded JSONL record");
  }
  const envelope = plain(JSON.parse(raw.slice(0, -1)), "provider envelope");
  if (envelope.operation === "attest") {
    assertOuterIdentity(envelope, false);
    return attestation(envelope);
  }
  if (envelope.operation === "conformance") {
    assertOuterIdentity(envelope, false);
    return conformance(envelope);
  }
  if (envelope.operation === "invoke") {
    assertOuterIdentity(envelope, true);
    return await invoke(envelope.request);
  }
  throw new Error("unreviewed provider operation");
}

main().then(
  (result) => process.stdout.write(JSON.stringify({ ok: true, result }) + "\\n"),
  (error) => process.stdout.write(JSON.stringify({
    ok: false,
    error: {
      code: "reviewed_fixture_provider_rejected",
      message: error instanceof Error ? error.message.slice(0, 500) : "provider rejected request",
    },
  }) + "\\n"),
);
`;
}

export function completeAutonomousCandidateProcedureSourceSha256(
  input: CompleteAutonomousCandidateProcedureSourceInput,
): string {
  return createHash("sha256")
    .update(renderCompleteAutonomousCandidateProcedureProvider(input), "utf8")
    .digest("hex");
}

import { isIP } from "node:net";
import { isAbsolute, resolve, sep } from "node:path";
import {
  WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
  WINDOWS_IDENTITY_OPERATIONS,
  WindowsIdentityBoundaryError,
  type WindowsIdentityActionRequest,
  type WindowsIdentityCredentialReference,
} from "./types";
import { windowsIdentityFailure } from "./failureTaxonomy";

const PUBLIC_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const CREDENTIAL_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const SECRET_FIELD = /password|passwd|secret|token|hash|ticket|cookie|private.?key|api.?key/iu;
const CONTROL = /[\u0000-\u001f\u007f]/u;

function boundary(code: Parameters<typeof windowsIdentityFailure>[0]): never {
  const failure = windowsIdentityFailure(code);
  throw new WindowsIdentityBoundaryError(
    failure.code,
    failure.category,
    failure.humanMessage,
    failure.retryable,
  );
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])
    || actual.some((key) => SECRET_FIELD.test(key))) {
    boundary("windows_identity_request_invalid");
  }
}

function id(value: unknown): string {
  if (typeof value !== "string" || !PUBLIC_ID.test(value)) {
    boundary("windows_identity_request_invalid");
  }
  return value;
}

export function canonicalWindowsIdentityTarget(value: unknown): string {
  if (typeof value !== "string"
    || value.length < 1
    || value.length > 253
    || value !== value.trim()
    || CONTROL.test(value)
    || /[\s/@,\\\[\]]/u.test(value)
    || value.startsWith("-")
    || value.endsWith(".")) {
    boundary("windows_identity_target_not_canonical");
  }
  if (isIP(value) !== 0) {
    if (value !== value.toLowerCase() || value.includes("%")) {
      boundary("windows_identity_target_not_canonical");
    }
    return value;
  }
  if (value !== value.toLowerCase()
    || !value.split(".").every((label) => HOST_LABEL.test(label))) {
    boundary("windows_identity_target_not_canonical");
  }
  return value;
}

function credentialReference(value: unknown): WindowsIdentityCredentialReference | null {
  if (value === null) return null;
  if (!plainObject(value)) boundary("windows_identity_credential_reference_invalid");
  exactKeys(value, ["id", "kind"]);
  if (value.kind !== "systemd_credential_bundle"
    || typeof value.id !== "string"
    || !CREDENTIAL_ID.test(value.id)) {
    boundary("windows_identity_credential_reference_invalid");
  }
  return Object.freeze({ kind: value.kind, id: value.id });
}

export function parseWindowsIdentityActionRequest(value: unknown): WindowsIdentityActionRequest {
  if (!plainObject(value)) boundary("windows_identity_request_invalid");
  exactKeys(value, [
    "authenticationMode",
    "credentialReference",
    "journey",
    "logicalWorkspace",
    "missionId",
    "operation",
    "planVersion",
    "runId",
    "schemaVersion",
    "stepId",
    "target",
  ]);
  if (value.schemaVersion !== WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION
    || (value.journey !== "guided" && value.journey !== "autonomous")
    || typeof value.operation !== "string"
    || !(WINDOWS_IDENTITY_OPERATIONS as readonly string[]).includes(value.operation)
    || (value.authenticationMode !== "anonymous" && value.authenticationMode !== "credential_reference")
    || typeof value.planVersion !== "number"
    || !Number.isSafeInteger(value.planVersion)
    || value.planVersion < 1
    || typeof value.logicalWorkspace !== "string"
    || value.logicalWorkspace.length < 2
    || value.logicalWorkspace.length > 4_096
    || !isAbsolute(value.logicalWorkspace)
    || resolve(value.logicalWorkspace) !== value.logicalWorkspace
    || value.logicalWorkspace === resolve(sep)
    || CONTROL.test(value.logicalWorkspace)) {
    boundary("windows_identity_request_invalid");
  }
  const reference = credentialReference(value.credentialReference);
  if ((value.authenticationMode === "credential_reference") !== (reference !== null)) {
    boundary("windows_identity_credential_reference_invalid");
  }
  return Object.freeze({
    schemaVersion: value.schemaVersion,
    missionId: id(value.missionId),
    runId: id(value.runId),
    stepId: id(value.stepId),
    planVersion: value.planVersion,
    journey: value.journey,
    operation: value.operation as WindowsIdentityActionRequest["operation"],
    target: canonicalWindowsIdentityTarget(value.target),
    logicalWorkspace: value.logicalWorkspace,
    authenticationMode: value.authenticationMode,
    credentialReference: reference,
  });
}

import type { RuntimeSourceManifests } from "../domain";
import type { GuidedMissionRequest } from "../missions";
import {
  WINDOWS_IDENTITY_OPERATIONS,
  WINDOWS_IDENTITY_OPERATION_PRESENTATION,
  WindowsIdentityToolPack,
  type WindowsIdentityAuthenticationMode,
} from "../windows-identity-tools";
import type { IntakeRegistrySnapshot } from "./types";

type Selection = NonNullable<GuidedMissionRequest["guidedWindowsIdentity"]>;

const pack = new WindowsIdentityToolPack();
const credentialOnlyToolId = pack.resolveOperation("smb_identity_summary")!.toolId;
const STABLE_REFERENCE = /^[A-Za-z0-9._:@/-]{1,200}$/u;

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/**
 * Projects the reviewed executable pack into intake product data. The UI never
 * owns its own operation list, authentication rules, or readiness claims.
 */
export function buildGuidedWindowsIdentityRegistry(
  manifests: RuntimeSourceManifests,
): IntakeRegistrySnapshot["guidedWindowsIdentity"] {
  const tools = new Map(manifests.tools.map((tool) => [tool.id, tool]));
  // The credential-only binding can become ready only when the shared private
  // credential resolver is configured and has passed its runtime boundary.
  // Using it as the mode receipt keeps mixed anonymous/credential tools from
  // claiming credential readiness merely because their anonymous path works.
  const credentialReferenceReady = tools.get(credentialOnlyToolId)?.available === true;
  return {
    registryVersion: 1,
    sourceOfTruth: "reviewed-windows-identity-tool-pack",
    modes: pack.definitions.map((definition) => {
      const tool = tools.get(definition.toolId);
      const toolReady = tool?.available === true
        && tool.locallyPolicyEnforced
        && tool.executionJourneys?.includes("guided") === true;
      const readyAuthenticationModes = definition.authenticationModes.filter(
        (mode) => toolReady
          && (mode === "anonymous" || credentialReferenceReady),
      );
      const presentation =
        WINDOWS_IDENTITY_OPERATION_PRESENTATION[definition.operation];
      const readiness = readyAuthenticationModes.length > 0
        ? "ready" as const
        : "unavailable" as const;
      const readinessExplanation = readiness === "ready"
        ? readyAuthenticationModes.includes("credential_reference")
          ? "The reviewed executable, private credential resolver, direct-argument sandbox, output limit, and cancellation boundary have current runtime receipts."
          : "The reviewed anonymous read, direct-argument sandbox, output limit, and cancellation boundary have current runtime receipts."
        : !tool
          ? "This reviewed operation is not present in the current runtime capability projection."
          : !tool.available
            ? "The operation is registered, but its executable or required private credential resolver has no complete current activation receipt."
            : "The operation is not mounted as a locally enforced Guided-only binding.";
      return {
        id: definition.operation,
        label: presentation.title,
        description: presentation.description,
        expectedResult: presentation.expectedResult,
        toolId: definition.toolId,
        authenticationModes: [...definition.authenticationModes],
        readyAuthenticationModes,
        readiness,
        readinessExplanation,
        remediation: readiness === "ready"
          ? "Choose one ready authentication mode. Ti-Scale will still wait for approval of the exact represented action."
          : definition.authenticationModes.includes("credential_reference")
            ? "Restore the exact executable receipt and configure the private systemd credential root, then repeat startup readiness."
            : "Restore the exact reviewed executable and repeat the isolated target-free startup readiness check.",
        requiresSingleStepAgent: true as const,
      };
    }),
  };
}

export function parseGuidedWindowsIdentitySelection(
  value: unknown,
): Readonly<{ selection?: Selection; issues: readonly string[] }> {
  if (value === undefined || value === null) return { issues: [] };
  const issues: string[] = [];
  if (!isRecord(value)) {
    return { issues: ["guidedWindowsIdentity must be an object."] };
  }
  if (!exactKeys(value, ["operation", "authenticationMode", "credentialReference"])) {
    issues.push("guidedWindowsIdentity must contain only operation, authenticationMode, and credentialReference.");
  }
  const operation = typeof value.operation === "string"
    && (WINDOWS_IDENTITY_OPERATIONS as readonly string[]).includes(value.operation)
    ? value.operation as Selection["operation"]
    : undefined;
  if (!operation) {
    issues.push("guidedWindowsIdentity.operation must be one reviewed Windows or identity operation.");
  }
  const authenticationMode =
    value.authenticationMode === "anonymous"
      || value.authenticationMode === "credential_reference"
      ? value.authenticationMode as WindowsIdentityAuthenticationMode
      : undefined;
  if (!authenticationMode) {
    issues.push("guidedWindowsIdentity.authenticationMode must be anonymous or credential_reference.");
  }
  let credentialReference: Selection["credentialReference"] = null;
  if (authenticationMode === "credential_reference") {
    if (
      !isRecord(value.credentialReference)
      || !exactKeys(value.credentialReference, ["kind", "id"])
      || value.credentialReference.kind !== "systemd_credential_bundle"
      || typeof value.credentialReference.id !== "string"
      || !STABLE_REFERENCE.test(value.credentialReference.id)
    ) {
      issues.push("guidedWindowsIdentity.credentialReference must be one opaque systemd_credential_bundle reference without credential material.");
    } else {
      credentialReference = {
        kind: "systemd_credential_bundle",
        id: value.credentialReference.id,
      };
    }
  } else if (
    authenticationMode === "anonymous"
    && value.credentialReference !== null
    && value.credentialReference !== undefined
  ) {
    issues.push("guidedWindowsIdentity.credentialReference must be null for anonymous reads.");
  }
  if (operation && authenticationMode) {
    const definition = pack.resolveOperation(operation);
    if (!definition?.authenticationModes.includes(authenticationMode)) {
      issues.push(`${operation} does not support ${authenticationMode} authentication.`);
    }
  }
  return issues.length > 0 || !operation || !authenticationMode
    ? { issues }
    : {
        issues,
        selection: { operation, authenticationMode, credentialReference },
      };
}

import { describe, expect, test } from "bun:test";
import type { RuntimeSourceManifests } from "../../../server/domain";
import {
  MissionIntakeService,
  MissionIntakeValidationError,
} from "../../../server/intake/MissionIntakeService";
import { validateMissionIntakeRequest } from "../../../server/intake/validation";
import {
  WindowsIdentityToolPack,
} from "../../../server/windows-identity-tools";
import { completeRuntimeManifests } from "../domain/fixtures";

function identityManifests(
  readyToolIds: readonly string[],
): RuntimeSourceManifests {
  const base = completeRuntimeManifests();
  const definitions = new WindowsIdentityToolPack().definitions;
  return {
    ...base,
    tools: [
      ...base.tools,
      ...definitions.map((definition) => ({
        id: definition.toolId,
        label: definition.label,
        available: readyToolIds.includes(definition.toolId),
        locallyPolicyEnforced: true,
        executionJourneys: ["guided"] as const,
        actionClassIds: [definition.actionClassId],
        evidenceTypeIds: [definition.evidenceTypeId],
        riskClassIds: ["runtime-risk"],
      })),
    ],
  };
}

function service(
  readyToolIds: readonly string[] = [
    "kali:smbclient-share-list",
    "kali:ldapsearch-root-dse",
    "kali:rpcclient-domain-info",
  ],
): MissionIntakeService {
  return new MissionIntakeService({
    readRuntimeManifests: () => identityManifests(readyToolIds),
    clock: () => new Date("2026-07-28T12:00:00.000Z"),
  });
}

describe("Guided Windows and identity intake", () => {
  test("publishes the reviewed tool pack with exact operation and authentication readiness", () => {
    const registry = service().snapshot("guided", "active_directory_lab")
      .guidedWindowsIdentity;
    expect(registry.registryVersion).toBe(1);
    expect(registry.sourceOfTruth).toBe("reviewed-windows-identity-tool-pack");
    expect(registry.modes.map(({ id, toolId }) => ({ id, toolId }))).toEqual([
      { id: "smb_share_list", toolId: "kali:smbclient-share-list" },
      { id: "smb_identity_summary", toolId: "kali:nxc-smb-summary" },
      { id: "ldap_root_dse", toolId: "kali:ldapsearch-root-dse" },
      { id: "rpc_domain_info", toolId: "kali:rpcclient-domain-info" },
    ]);
    expect(registry.modes.find(({ id }) => id === "smb_share_list"))
      .toMatchObject({
        readiness: "ready",
        readyAuthenticationModes: ["anonymous"],
        requiresSingleStepAgent: true,
      });
    expect(registry.modes.find(({ id }) => id === "smb_identity_summary"))
      .toMatchObject({
        readiness: "unavailable",
        readyAuthenticationModes: [],
      });
    expect(registry.modes.every(({ description, expectedResult }) =>
      description.length > 80 && expectedResult.length > 60)).toBeTrue();
  });

  test("normalizes one exact anonymous operation into the durable Guided contract", () => {
    const request = validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "dc01.lab.test" }],
      executionPreference: "single_step_agent",
      guidedWindowsIdentity: {
        operation: "ldap_root_dse",
        authenticationMode: "anonymous",
        credentialReference: null,
      },
    });
    const resolved = service().resolve(request);
    expect(resolved.request.journey).toBe("guided");
    if (resolved.request.journey !== "guided") throw new Error("Expected Guided request");
    expect(resolved.request.guidedWindowsIdentity).toEqual({
      operation: "ldap_root_dse",
      authenticationMode: "anonymous",
      credentialReference: null,
    });
  });

  test("rejects ambiguous, manual, unavailable, and credential-bearing input", () => {
    expect(() => service().resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.20" }],
      executionPreference: "manual",
      guidedWindowsIdentity: {
        operation: "ldap_root_dse",
        authenticationMode: "anonymous",
        credentialReference: null,
      },
    })).toThrow("requires “Run one represented step for me”");

    expect(() => service().resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.20" }],
      executionPreference: "single_step_agent",
      guidedReconnaissance: { mode: "host_liveness" },
      guidedWindowsIdentity: {
        operation: "ldap_root_dse",
        authenticationMode: "anonymous",
        credentialReference: null,
      },
    })).toThrow("either one reconnaissance step or one Windows or identity read");

    expect(() => service().resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.20" }],
      executionPreference: "single_step_agent",
      guidedWindowsIdentity: {
        operation: "smb_identity_summary",
        authenticationMode: "credential_reference",
        credentialReference: {
          kind: "systemd_credential_bundle",
          id: "lab-credential",
        },
      },
    })).toThrow(MissionIntakeValidationError);

    expect(() => validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.20" }],
      executionPreference: "single_step_agent",
      guidedWindowsIdentity: {
        operation: "ldap_root_dse",
        authenticationMode: "credential_reference",
        credentialReference: {
          kind: "systemd_credential_bundle",
          id: "password=not-allowed",
        },
      },
    })).toThrow("does not support credential_reference");
  });

  test("enables private-reference options only when the credential-resolver runtime binding is ready", () => {
    const registry = service([
      "kali:smbclient-share-list",
      "kali:nxc-smb-summary",
      "kali:ldapsearch-root-dse",
      "kali:rpcclient-domain-info",
    ]).snapshot("guided", "active_directory_lab").guidedWindowsIdentity;
    expect(registry.modes.find(({ id }) => id === "smb_share_list")
      ?.readyAuthenticationModes).toEqual(["anonymous", "credential_reference"]);
    expect(registry.modes.find(({ id }) => id === "smb_identity_summary"))
      .toMatchObject({
        readiness: "ready",
        readyAuthenticationModes: ["anonymous", "credential_reference"],
      });
  });
});

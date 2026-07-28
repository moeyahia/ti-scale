import { describe, expect, test } from "bun:test";
import type { RuntimeSourceManifests } from "../../../server/domain";
import { MissionIntakeService } from "../../../server/intake/MissionIntakeService";
import { WindowsIdentityToolPack } from "../../../server/windows-identity-tools";
import {
  parseIntakeRegistrySnapshot,
  parseResolvedMissionIntake,
} from "../../../src/domain/schemas/intake";
import { completeRuntimeManifests } from "../domain/fixtures";

function manifests(): RuntimeSourceManifests {
  const base = completeRuntimeManifests();
  const ready = new Set([
    "kali:smbclient-share-list",
    "kali:ldapsearch-root-dse",
    "kali:rpcclient-domain-info",
  ]);
  return {
    ...base,
    tools: [
      ...base.tools,
      ...new WindowsIdentityToolPack().definitions.map((definition) => ({
        id: definition.toolId,
        label: definition.label,
        available: ready.has(definition.toolId),
        locallyPolicyEnforced: true,
        executionJourneys: ["guided"] as const,
        actionClassIds: [definition.actionClassId],
        evidenceTypeIds: [definition.evidenceTypeId],
        riskClassIds: ["runtime-risk"],
      })),
    ],
  };
}

describe("Guided Windows and identity intake client contract", () => {
  test("parses server-owned modes and the exact normalized mission selection", () => {
    const service = new MissionIntakeService({
      readRuntimeManifests: manifests,
      clock: () => new Date("2026-07-28T12:00:00.000Z"),
    });
    const registry = parseIntakeRegistrySnapshot(
      service.snapshot("guided", "active_directory_lab"),
    );
    expect(registry.guidedWindowsIdentity.modes).toHaveLength(4);
    expect(registry.guidedWindowsIdentity.modes.find(
      ({ id }) => id === "ldap_root_dse",
    )).toMatchObject({
      readiness: "ready",
      authenticationModes: ["anonymous"],
      readyAuthenticationModes: ["anonymous"],
      requiresSingleStepAgent: true,
    });

    const resolved = parseResolvedMissionIntake(service.resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "dc01.lab.test" }],
      executionPreference: "single_step_agent",
      guidedWindowsIdentity: {
        operation: "ldap_root_dse",
        authenticationMode: "anonymous",
        credentialReference: null,
      },
    }));
    expect(resolved.request.journey).toBe("guided");
    if (resolved.request.journey !== "guided") throw new Error("Expected Guided request");
    expect(resolved.request.guidedWindowsIdentity).toEqual({
      operation: "ldap_root_dse",
      authenticationMode: "anonymous",
      credentialReference: null,
    });
  });

  test("rejects contradictory registry readiness and credential material on an anonymous selection", () => {
    const service = new MissionIntakeService({
      readRuntimeManifests: manifests,
      clock: () => new Date("2026-07-28T12:00:00.000Z"),
    });
    const contradictory = structuredClone(
      service.snapshot("guided", "active_directory_lab"),
    );
    const ldap = contradictory.guidedWindowsIdentity.modes.find(
      ({ id }) => id === "ldap_root_dse",
    );
    if (!ldap) throw new Error("Expected LDAP registry mode");
    Object.assign(ldap, {
      readiness: "unavailable",
      readyAuthenticationModes: ["anonymous"],
    });
    expect(() => parseIntakeRegistrySnapshot(contradictory))
      .toThrow("readiness contradicts");

    const resolved = structuredClone(service.resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "dc01.lab.test" }],
      executionPreference: "single_step_agent",
      guidedWindowsIdentity: {
        operation: "ldap_root_dse",
        authenticationMode: "anonymous",
        credentialReference: null,
      },
    }));
    if (resolved.request.journey !== "guided") throw new Error("Expected Guided request");
    const invalidAnonymousSelection = {
      ...resolved,
      request: {
        ...resolved.request,
        guidedWindowsIdentity: {
          ...resolved.request.guidedWindowsIdentity!,
          credentialReference: {
            kind: "systemd_credential_bundle",
            id: "must-not-be-present",
          },
        },
      },
    };
    expect(() => parseResolvedMissionIntake(invalidAnonymousSelection))
      .toThrow("must not contain a credential reference");
  });
});

import { describe, expect, test } from "bun:test";
import { validateMissionCreateRequest } from "../validation";
import { MissionValidationError } from "../errors";

function request(overrides: Record<string, unknown> = {}) {
  return {
    journey: "guided",
    launch: true,
    authorizationConfirmed: true,
    title: "Reviewed identity baseline",
    objective: "Read one bounded identity metadata record from the exact approved host",
    target: "127.0.0.1",
    explanationDepth: "balanced",
    executionPreference: "single_step_agent",
    evidenceExpectations: [],
    guidedWindowsIdentity: {
      operation: "smb_share_list",
      authenticationMode: "anonymous",
      credentialReference: null,
    },
    ...overrides,
  };
}

describe("Guided Windows/identity mission intake", () => {
  test("accepts one anonymous reviewed operation without credential material", () => {
    expect(validateMissionCreateRequest(request())).toMatchObject({
      journey: "guided",
      target: "127.0.0.1",
      guidedWindowsIdentity: {
        operation: "smb_share_list",
        authenticationMode: "anonymous",
        credentialReference: null,
      },
    });
  });

  test("accepts only an opaque credential reference for the credential-required binding", () => {
    expect(validateMissionCreateRequest(request({
      guidedWindowsIdentity: {
        operation: "smb_identity_summary",
        authenticationMode: "credential_reference",
        credentialReference: { kind: "systemd_credential_bundle", id: "fixture-ref" },
      },
    }))).toMatchObject({
      guidedWindowsIdentity: {
        operation: "smb_identity_summary",
        credentialReference: { id: "fixture-ref" },
      },
    });
    try {
      validateMissionCreateRequest(request({
        guidedWindowsIdentity: {
          operation: "smb_identity_summary",
          authenticationMode: "credential_reference",
          credentialReference: { kind: "systemd_credential_bundle", id: "fixture-ref", password: "secret" },
        },
      }));
      throw new Error("Expected credential-bearing intake to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(MissionValidationError);
      expect((error as MissionValidationError).issues.join(" ")).toContain(
        "without credential material or extra fields",
      );
    }
  });

  test("rejects two competing first-step selections", () => {
    try {
      validateMissionCreateRequest(request({
        guidedReconnaissance: { mode: "host_liveness" },
      }));
      throw new Error("Expected ambiguous first-step intake to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(MissionValidationError);
      expect((error as MissionValidationError).issues.join(" ")).toContain(
        "choose either guidedReconnaissance or guidedWindowsIdentity",
      );
    }
  });
});

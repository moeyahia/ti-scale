import { describe, expect, test } from "bun:test";
import { fingerprintAction, type ActionIntent, type GuidedDecision } from "../../supervisor";
import {
  WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
  WindowsIdentityBoundaryError,
  type WindowsIdentityActionRequest,
  type WindowsIdentityCredentialBindingReceipt,
  type WindowsIdentityMissionBoundary,
} from "../types";
import { WindowsIdentityToolPack } from "../WindowsIdentityToolPack";

const NOW = new Date("2026-07-20T09:00:00.000Z");

function request(
  overrides: Partial<WindowsIdentityActionRequest> = {},
): WindowsIdentityActionRequest {
  return {
    schemaVersion: WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
    missionId: "mission-identity-1",
    runId: "run-identity-1",
    stepId: "step-identity-1",
    planVersion: 1,
    journey: "guided",
    operation: "smb_share_list",
    target: "10.10.10.10",
    logicalWorkspace: "/engagements/engagement-identity",
    authenticationMode: "anonymous",
    credentialReference: null,
    ...overrides,
  };
}

function actionFor(
  pack: WindowsIdentityToolPack,
  value: WindowsIdentityActionRequest,
): ActionIntent {
  const definition = pack.resolveOperation(value.operation)!;
  return {
    missionId: value.missionId,
    runId: value.runId,
    stepId: value.stepId,
    planVersion: value.planVersion,
    actionType: definition.toolId,
    actionClass: definition.actionClassId,
    target: value.target,
    arguments: {
      schemaVersion: value.schemaVersion,
      executionBinding: "reviewed_windows_identity_process",
      operation: value.operation,
      toolId: definition.toolId,
      authenticationMode: value.authenticationMode,
      credentialReference: value.credentialReference,
      logicalWorkspace: value.logicalWorkspace,
    },
  };
}

function boundaryFor(
  pack: WindowsIdentityToolPack,
  value: WindowsIdentityActionRequest,
): WindowsIdentityMissionBoundary {
  const represented = actionFor(pack, value);
  const decision: GuidedDecision = {
    id: "decision-identity-1",
    missionId: value.missionId,
    runId: value.runId,
    stepId: value.stepId,
    journey: "guided",
    actionFingerprint: fingerprintAction(represented).hash,
    status: "authorized",
    authorizedAt: NOW.toISOString(),
    expiresAt: "2026-07-20T09:30:00.000Z",
    version: 1,
  };
  return {
    authorizationVerified: true,
    allowedTargets: [value.target],
    prohibitedTargets: [],
    allowedActionClassIds: ["active_directory_identity_operations"],
    prohibitedActionClassIds: [],
    guidedDecision: decision,
  };
}

function compile(
  pack: WindowsIdentityToolPack,
  value: WindowsIdentityActionRequest,
  credentialBindingReceipt: WindowsIdentityCredentialBindingReceipt | null = null,
) {
  return pack.compile({
    request: value,
    missionBoundary: boundaryFor(pack, value),
    credentialBindingReceipt,
    now: NOW,
  });
}

describe("reviewed Windows identity tool pack", () => {
  test("declares four read-only, direct-argv, Guided-only tool bindings", () => {
    const pack = new WindowsIdentityToolPack();
    expect(pack.definitions.map(({ toolId }) => toolId)).toEqual([
      "kali:smbclient-share-list",
      "kali:nxc-smb-summary",
      "kali:ldapsearch-root-dse",
      "kali:rpcclient-domain-info",
    ]);
    expect(pack.definitions.every((definition) =>
      definition.journeyPolicy === "guided_only"
      && definition.execution.directArgv
      && definition.execution.shell === false
      && definition.execution.readOnlyTargetOperation
      && definition.probe.targetContact === false)).toBeTrue();
  });

  test("compiles one exact anonymous SMB read without shell or evidence promotion", () => {
    const pack = new WindowsIdentityToolPack();
    const invocation = compile(pack, request());
    expect(invocation).toMatchObject({
      toolId: "kali:smbclient-share-list",
      target: "10.10.10.10",
      executablePath: "/usr/bin/smbclient",
      shell: false,
      directArgv: true,
      targetReadOnly: true,
      evidencePromotion: "none",
      credentialReference: null,
      credentialBindingReceipt: null,
    });
    expect(invocation.arguments).toContain("--no-pass");
    expect(invocation.arguments).toContain("--list=10.10.10.10");
  });

  test("uses only fixed private-file paths for an opaque NetExec credential reference", () => {
    const pack = new WindowsIdentityToolPack();
    const value = request({
      operation: "smb_identity_summary",
      authenticationMode: "credential_reference",
      credentialReference: { kind: "systemd_credential_bundle", id: "cred-ref-1" },
    });
    const fingerprint = fingerprintAction(actionFor(pack, value)).hash;
    const receipt: WindowsIdentityCredentialBindingReceipt = {
      schemaVersion: "ti-scale.windows-identity-credential-binding.v1",
      referenceId: "cred-ref-1",
      runId: value.runId,
      actionFingerprint: fingerprint,
      availableViews: ["username_file", "password_file"],
      mountedReadOnly: true,
      privateToProcess: true,
      expiresAt: "2026-07-20T09:10:00.000Z",
      grantsAuthorization: false,
    };
    const invocation = compile(pack, value, receipt);
    expect(invocation.arguments).toContain("/run/ti-scale/credential/username");
    expect(invocation.arguments).toContain("/run/ti-scale/credential/password");
    expect(invocation.arguments.join(" ")).not.toContain("cred-ref-1");
    expect(invocation.arguments).toContain("--no-write-check");
    expect(invocation.arguments).toContain("--no-bruteforce");
  });

  test("rejects Autonomous use, target injection, scope drift, and changed Guided actions", () => {
    const pack = new WindowsIdentityToolPack();
    const autonomous = request({ journey: "autonomous" });
    expect(() => pack.compile({
      request: autonomous,
      missionBoundary: boundaryFor(pack, autonomous),
      credentialBindingReceipt: null,
      now: NOW,
    })).toThrow("Guided-only");
    expect(() => compile(pack, request({ target: "--option=bad" }))).toThrow(
      "canonical IP address or lowercase hostname",
    );

    const represented = request();
    const changed = request({ target: "10.10.10.11" });
    expect(() => pack.compile({
      request: changed,
      missionBoundary: {
        ...boundaryFor(pack, represented),
        allowedTargets: [changed.target],
      },
      credentialBindingReceipt: null,
      now: NOW,
    })).toThrow("changed after the Guided decision");

    try {
      pack.compile({
        request: represented,
        missionBoundary: { ...boundaryFor(pack, represented), allowedTargets: [] },
        credentialBindingReceipt: null,
        now: NOW,
      });
      throw new Error("expected scope rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(WindowsIdentityBoundaryError);
      expect((error as WindowsIdentityBoundaryError).code)
        .toBe("windows_identity_target_outside_scope");
    }
  });
});

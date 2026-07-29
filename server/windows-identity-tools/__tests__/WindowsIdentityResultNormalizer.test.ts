import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { normalizeWindowsIdentityResult, redactWindowsIdentityOutput } from "../WindowsIdentityResultNormalizer";
import type {
  WindowsIdentityFailureCode,
  WindowsIdentityNormalizedResult,
  WindowsIdentityRawResult,
  WindowsIdentityToolId,
} from "../types";

function raw(
  toolId: WindowsIdentityToolId,
  overrides: Partial<WindowsIdentityRawResult> = {},
): WindowsIdentityRawResult {
  return {
    schemaVersion: "ti-scale.windows-identity-result.v1",
    toolId,
    actionFingerprint: "a".repeat(64),
    exitCode: 0,
    signal: null,
    stdout: "",
    stderr: "",
    observedOutputBytes: 0,
    retainedOutputBytes: 0,
    outputSha256: "b".repeat(64),
    outputTruncated: false,
    timedOut: false,
    cancelled: false,
    startedAt: "2026-07-20T10:00:00.000Z",
    endedAt: "2026-07-20T10:00:01.000Z",
    receipt: {
      schemaVersion: "ti-scale.windows-identity-execution-receipt.v1",
      adapterId: "adapter-fixture",
      toolId,
      actionFingerprint: "a".repeat(64),
      runId: "run-fixture",
      executableSha256: "c".repeat(64),
      sandboxExecutableSha256: "d".repeat(64),
      logicalWorkspace: "/engagements/fixture",
      credentialReferenceId: null,
      directArgv: true,
      shell: false,
      targetReadOnly: true,
      workspaceConfined: true,
      credentialsMountedReadOnly: true,
      outputRedacted: true,
      outputSha256: "b".repeat(64),
      startedAt: "2026-07-20T10:00:00.000Z",
      endedAt: "2026-07-20T10:00:01.000Z",
      wallClockMs: 1_000,
      exitCode: 0,
      signal: null,
      timedOut: false,
      cancelled: false,
      outputTruncated: false,
      grantsAuthorization: false,
    },
    ...overrides,
  };
}

describe("WindowsIdentityResultNormalizer", () => {
  test("redacts reusable authentication material before hashing or retaining an engagement log", () => {
    const privateKey = "-----BEGIN PRIVATE KEY-----\nfixture-private-material\n-----END PRIVATE KEY-----";
    const source = [
      "password=NeverReturnThis",
      "Authorization: Bearer abc.def.ghi",
      "Bearer abcdef123456",
      "0123456789abcdef0123456789abcdef:fedcba9876543210fedcba9876543210",
      "-U WORKGROUP\\user%InlinePassword",
      privateKey,
    ].join("\n");
    const redacted = redactWindowsIdentityOutput(source);
    expect(redacted).not.toContain("NeverReturnThis");
    expect(redacted).not.toContain("abc.def.ghi");
    expect(redacted).not.toContain("abcdef123456");
    expect(redacted).not.toContain("0123456789abcdef");
    expect(redacted).not.toContain("InlinePassword");
    expect(redacted).not.toContain("fixture-private-material");

    const normalized = normalizeWindowsIdentityResult(raw("kali:smbclient-share-list", {
      stdout: source,
      observedOutputBytes: Buffer.byteLength(source),
      retainedOutputBytes: Buffer.byteLength(source),
    }));
    const expectedHash = createHash("sha256")
      .update(normalized.engagementLog.stdout, "utf8")
      .update("\u0000", "utf8")
      .update(normalized.engagementLog.stderr, "utf8")
      .digest("hex");
    expect(normalized.engagementLog.outputSha256).toBe(expectedHash);
    expect(JSON.stringify(normalized)).not.toContain("NeverReturnThis");
    expect(normalized.evidenceCandidates).toEqual([]);
    expect(normalized.verifiedEvidence).toEqual([]);
  });

  test("parses read-only SMB, NetExec, LDAP, and RPC observations but leaves every item unverified", () => {
    const cases: readonly [WindowsIdentityToolId, string, string][] = [
      ["kali:smbclient-share-list", "Disk|IPC$|Remote IPC\nDisk|Public|Shared files", "smb_share"],
      ["kali:nxc-smb-summary", "SMB 127.0.0.1 445 HOST [*] Windows 11 (domain:LAB) (signing:True) (SMBv1:False)", "smb_host_identity"],
      ["kali:ldapsearch-root-dse", "defaultNamingContext: DC=lab,DC=test\ndnsHostName: dc.lab.test", "ldap_directory_metadata"],
      ["kali:rpcclient-domain-info", "Domain: LAB\nServer Role: ROLE_DOMAIN_PDC", "rpc_domain_metadata"],
    ];
    for (const [toolId, stdout, expectedType] of cases) {
      const normalized = normalizeWindowsIdentityResult(raw(toolId, { stdout }));
      expect(normalized.status).toBe("completed");
      expect(normalized.observations.length).toBeGreaterThan(0);
      expect(normalized.observations[0]).toMatchObject({
        type: expectedType,
        sourceToolId: toolId,
        verified: false,
      });
      expect(normalized.evidenceCandidates).toEqual([]);
      expect(normalized.verifiedEvidence).toEqual([]);
    }
  });

  test("classifies timeout, output-limit, cancellation, authentication, reachability, and deterministic errors", () => {
    const cases: readonly [
      Partial<WindowsIdentityRawResult>,
      WindowsIdentityNormalizedResult["status"],
      WindowsIdentityFailureCode,
    ][] = [
      [{ timedOut: true, exitCode: null }, "failed", "windows_identity_timed_out"],
      [{ outputTruncated: true, exitCode: null }, "failed", "windows_identity_output_limit"],
      [{ cancelled: true, exitCode: null }, "cancelled", "windows_identity_cancelled"],
      [{ exitCode: 1, stderr: "NT_STATUS_LOGON_FAILURE" }, "failed", "windows_identity_authentication_rejected"],
      [{ exitCode: 1, stderr: "No route to host" }, "failed", "windows_identity_target_unreachable"],
      [{ exitCode: 2, stderr: "invalid option" }, "failed", "windows_identity_tool_deterministic_error"],
    ];
    for (const [overrides, status, code] of cases) {
      const normalized = normalizeWindowsIdentityResult(raw("kali:smbclient-share-list", overrides));
      expect(normalized.status).toBe(status);
      expect(normalized.failure?.code).toBe(code);
      expect(normalized.observations).toEqual([]);
      expect(normalized.evidenceCandidates).toEqual([]);
      expect(normalized.verifiedEvidence).toEqual([]);
    }
  });
});

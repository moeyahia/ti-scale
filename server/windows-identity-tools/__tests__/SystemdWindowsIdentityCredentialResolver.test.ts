import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SystemdWindowsIdentityCredentialResolver } from "../SystemdWindowsIdentityCredentialResolver";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-identity-credentials-"));
  roots.push(root);
  const bundle = join(root, "operator-ref");
  mkdirSync(bundle, { mode: 0o700 });
  writeFileSync(join(bundle, "username"), "operator\n", { mode: 0o600 });
  writeFileSync(join(bundle, "password"), "not-returned\n", { mode: 0o600 });
  return { root, bundle };
}

describe("SystemdWindowsIdentityCredentialResolver", () => {
  test("returns only private host paths and an expiring non-authorizing receipt", async () => {
    const { root, bundle } = fixture();
    let now = new Date("2026-07-20T12:00:00.000Z");
    const resolver = new SystemdWindowsIdentityCredentialResolver(root, () => now);
    expect(await resolver.readiness()).toBeTrue();
    const result = await resolver.resolve({
      reference: { kind: "systemd_credential_bundle", id: "operator-ref" },
      runId: "run_fixture",
      actionFingerprint: "a".repeat(64),
      requiredViews: ["username_file", "password_file"],
    });
    expect(result.receipt).toMatchObject({
      referenceId: "operator-ref",
      runId: "run_fixture",
      availableViews: ["username_file", "password_file"],
      mountedReadOnly: true,
      privateToProcess: true,
      expiresAt: "2026-07-20T12:00:30.000Z",
      grantsAuthorization: false,
    });
    expect(result.files).toEqual({
      username_file: join(bundle, "username"),
      password_file: join(bundle, "password"),
    });
    expect(JSON.stringify(result)).not.toContain("not-returned");
    now = new Date("2026-07-20T12:00:00.005Z");
    const repeated = await resolver.resolve({
      reference: { kind: "systemd_credential_bundle", id: "operator-ref" },
      runId: "run_fixture",
      actionFingerprint: "a".repeat(64),
      requiredViews: ["username_file", "password_file"],
    });
    expect(repeated).toBe(result);
    expect(repeated.receipt.expiresAt).toBe("2026-07-20T12:00:30.000Z");
  });

  test("rejects traversal, symlinked views, and missing views", async () => {
    const { root, bundle } = fixture();
    const resolver = new SystemdWindowsIdentityCredentialResolver(root);
    await expect(resolver.resolve({
      reference: { kind: "systemd_credential_bundle", id: "../escape" },
      runId: "run_fixture",
      actionFingerprint: "a".repeat(64),
      requiredViews: ["username_file"],
    })).rejects.toThrow("not canonical");
    rmSync(join(bundle, "username"));
    symlinkSync("/etc/hosts", join(bundle, "username"));
    await expect(resolver.resolve({
      reference: { kind: "systemd_credential_bundle", id: "operator-ref" },
      runId: "run_fixture",
      actionFingerprint: "a".repeat(64),
      requiredViews: ["username_file"],
    })).rejects.toThrow("missing, symlinked");
    await expect(resolver.resolve({
      reference: { kind: "systemd_credential_bundle", id: "operator-ref" },
      runId: "run_fixture",
      actionFingerprint: "a".repeat(64),
      requiredViews: ["samba_auth_file"],
    })).rejects.toThrow("missing, symlinked");
  });
});

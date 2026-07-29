import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SystemdCredentialStore,
  SystemdCredentialStoreError,
  systemdCredentialStoreFromEnvironment,
} from "../SystemdCredentialStore";

function directory(): string {
  return mkdtempSync(join(tmpdir(), "ti-scale-systemd-credential-"));
}

describe("SystemdCredentialStore", () => {
  test("reads one bounded credential from the private mount and strips one newline", () => {
    const root = directory();
    try {
      const path = join(root, "public-nvd-mcp-token");
      writeFileSync(path, "opaque-token-value\n", { mode: 0o400 });
      const store = new SystemdCredentialStore(root);
      const credential = store.read("public-nvd-mcp-token");
      expect(Buffer.from(credential).toString("utf8")).toBe("opaque-token-value");
      credential.fill(0);
      expect([...credential].every((value) => value === 0)).toBe(true);
      expect(readFileSync(path, "utf8")).toBe("opaque-token-value\n");
      expect(store.has("public-nvd-mcp-token")).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects traversal, symbolic links, control bytes, and missing values", () => {
    const root = directory();
    const outside = join(root, "outside-token");
    try {
      writeFileSync(outside, "outside-value", { mode: 0o400 });
      symlinkSync(outside, join(root, "linked-token"));
      writeFileSync(join(root, "control-token"), Buffer.from([0x61, 0x00, 0x62]), { mode: 0o400 });
      const store = new SystemdCredentialStore(root);
      expect(() => store.read("../outside-token")).toThrow(SystemdCredentialStoreError);
      expect(() => store.read("linked-token")).toThrow(SystemdCredentialStoreError);
      expect(() => store.read("control-token")).toThrow(SystemdCredentialStoreError);
      expect(store.has("missing-token")).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("uses only the non-secret systemd credential-directory environment entry", () => {
    const root = directory();
    try {
      expect(systemdCredentialStoreFromEnvironment({ CREDENTIALS_DIRECTORY: root })?.directory)
        .toBe(root);
      expect(systemdCredentialStoreFromEnvironment({})).toBeUndefined();
      expect(() => systemdCredentialStoreFromEnvironment({ CREDENTIALS_DIRECTORY: "relative" }))
        .toThrow(SystemdCredentialStoreError);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

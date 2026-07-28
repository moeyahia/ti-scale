import { afterEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
  chownSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OpenRouterPlanningError,
  readOpenRouterCredential,
  validateOpenRouterEndpoint,
} from "../../../../server/providers/openrouter";

const roots: string[] = [];
const KEY = "sk-or-v1-unit-test-credential-material";

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function credential(mode = 0o600): { root: string; path: string } {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-openrouter-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const path = join(root, "openrouter-api-key");
  writeFileSync(path, `${KEY}\n`, { encoding: "utf8", mode });
  chmodSync(path, mode);
  return { root, path };
}

function errorFrom(operation: () => unknown): OpenRouterPlanningError {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(OpenRouterPlanningError);
    return error as OpenRouterPlanningError;
  }
  throw new Error("Expected OpenRouterPlanningError");
}

describe("OpenRouter service credential boundary", () => {
  test("reads only an absolute private regular credential owned by root or the service uid", () => {
    const { path } = credential();
    expect(readOpenRouterCredential({ path })).toBe(KEY);
    const relative = errorFrom(() => readOpenRouterCredential({ path: "openrouter-api-key" }));
    expect(relative).toMatchObject({
      code: "openrouter_credential_path_invalid",
      category: "authentication_missing",
      retryable: false,
    });
  });

  test("rejects permissive file and parent modes", () => {
    const permissiveFile = credential(0o644);
    expect(errorFrom(() => readOpenRouterCredential({ path: permissiveFile.path })).code)
      .toBe("openrouter_credential_mode_invalid");

    const permissiveParent = credential();
    chmodSync(permissiveParent.root, 0o777);
    expect(errorFrom(() => readOpenRouterCredential({ path: permissiveParent.path })).code)
      .toBe("openrouter_credential_parent_permissions");
  });

  test("rejects a symlink even when its target is private", () => {
    const { root, path } = credential();
    const link = join(root, "linked-key");
    symlinkSync(path, link);
    expect(errorFrom(() => readOpenRouterCredential({ path: link })).code)
      .toBe("openrouter_credential_file_invalid");
  });

  test("rejects an owner other than root or the declared service uid when ownership can be changed", () => {
    const { path } = credential();
    if (typeof process.geteuid === "function" && process.geteuid() === 0) {
      chownSync(path, 65_534, 65_534);
      expect(errorFrom(() => readOpenRouterCredential({ path, serviceUid: 65_533 })).code)
        .toBe("openrouter_credential_owner_invalid");
    } else {
      // Non-root CI still exercises the same owner decision without requiring chown.
      const currentUid = typeof process.geteuid === "function"
        ? process.geteuid()
        : typeof process.getuid === "function" ? process.getuid() : 0;
      expect(readOpenRouterCredential({ path, serviceUid: currentUid })).toBe(KEY);
    }
  });

  test("never includes credential content in typed configuration failures", () => {
    const { path } = credential();
    writeFileSync(path, `${KEY} invalid whitespace`, { encoding: "utf8", mode: 0o600 });
    chmodSync(path, 0o600);
    const error = errorFrom(() => readOpenRouterCredential({ path }));
    expect(JSON.stringify(error)).not.toContain(KEY);
    expect(error.stack).not.toContain(KEY);
  });
});

describe("OpenRouter endpoint boundary", () => {
  test("allows only the fixed official HTTPS chat-completions route", () => {
    expect(validateOpenRouterEndpoint()).toBe("https://openrouter.ai/api/v1/chat/completions");
    for (const endpoint of [
      "http://openrouter.ai/api/v1/chat/completions",
      "https://evil.example/api/v1/chat/completions",
      "https://openrouter.ai/api/v1/other",
      "https://user:pass@openrouter.ai/api/v1/chat/completions",
      "https://openrouter.ai/api/v1/chat/completions?redirect=https://evil.example",
    ]) {
      expect(() => validateOpenRouterEndpoint(endpoint)).toThrow(OpenRouterPlanningError);
    }
  });
});

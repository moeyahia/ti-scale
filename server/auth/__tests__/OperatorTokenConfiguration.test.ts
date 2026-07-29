import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveOperatorToken } from "../OperatorTokenConfiguration";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-token-"));
  temporaryDirectories.push(directory);
  return directory;
}

describe("standalone operator token configuration", () => {
  test("loads one private absolute credential file with one optional trailing newline", () => {
    const directory = fixture();
    const path = join(directory, "operator-token");
    writeFileSync(path, "standalone-private-operator-token-2026\n", { mode: 0o600 });
    expect(resolveOperatorToken({ TI_SCALE_OPERATOR_TOKEN_FILE: path }))
      .toBe("standalone-private-operator-token-2026");
  });

  test("accepts the existing inline boundary but rejects ambiguous or weak configuration", () => {
    expect(resolveOperatorToken({ TI_SCALE_OPERATOR_TOKEN: "standalone-inline-operator-token-2026" }))
      .toBe("standalone-inline-operator-token-2026");
    expect(() => resolveOperatorToken({
      TI_SCALE_OPERATOR_TOKEN: "standalone-inline-operator-token-2026",
      TI_SCALE_OPERATOR_TOKEN_FILE: "/run/credentials/operator-token",
    })).toThrow("not both");
    expect(() => resolveOperatorToken({ TI_SCALE_OPERATOR_TOKEN: "short" })).toThrow("at least 24 bytes");
  });

  test("rejects relative, linked, broadly readable, multiline, and oversized credential files", () => {
    const directory = fixture();
    const secure = join(directory, "secure-token");
    writeFileSync(secure, "standalone-private-operator-token-2026", { mode: 0o600 });
    expect(() => resolveOperatorToken({ TI_SCALE_OPERATOR_TOKEN_FILE: "relative-token" })).toThrow("absolute");

    const link = join(directory, "linked-token");
    symlinkSync(secure, link);
    expect(() => resolveOperatorToken({ TI_SCALE_OPERATOR_TOKEN_FILE: link })).toThrow("regular file");

    chmodSync(secure, 0o640);
    expect(() => resolveOperatorToken({ TI_SCALE_OPERATOR_TOKEN_FILE: secure })).toThrow("group or other");

    const multiline = join(directory, "multiline-token");
    writeFileSync(multiline, "standalone-private-operator-token-2026\nsecond-line", { mode: 0o600 });
    expect(() => resolveOperatorToken({ TI_SCALE_OPERATOR_TOKEN_FILE: multiline })).toThrow("one bounded line");

    const oversized = join(directory, "oversized-token");
    writeFileSync(oversized, "x".repeat(4_098), { mode: 0o600 });
    expect(() => resolveOperatorToken({ TI_SCALE_OPERATOR_TOKEN_FILE: oversized })).toThrow("bounded size");
  });
});

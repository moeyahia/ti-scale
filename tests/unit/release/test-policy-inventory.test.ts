import {
  describe,
  expect,
  test,
} from "bun:test";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  findForbiddenModifiers,
  validateTestPolicy,
} from "../../../scripts/validate-test-policy";

describe("release test inventory policy", () => {
  test("accounts for every repository test file with no masking modifier", () => {
    const result = validateTestPolicy();
    expect(result.testFiles).toBeGreaterThan(500);
    expect(result.unitFiles).toBeGreaterThan(400);
    expect(result.browserFiles).toBeGreaterThan(50);
    expect(result.unitFiles + result.browserFiles).toBe(result.testFiles);
  });

  test("rejects suite-level retry configuration that could mask flakiness", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-test-policy-"));
    try {
      const path = join(root, "retry.spec.ts");
      writeFileSync(
        path,
        'test.describe.configure({ mode: "serial", retries: 1 });\n',
        "utf8",
      );
      expect(findForbiddenModifiers(path)).toEqual([
        expect.stringContaining("configures a non-zero test retry"),
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

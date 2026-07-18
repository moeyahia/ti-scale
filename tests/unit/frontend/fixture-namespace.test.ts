import { describe, expect, test } from "bun:test";
import { canonicalFixtureNamespace, normalizeFixtureNamespace } from "../../e2e/support/fixtureNamespace";

function identity(projectName: string, workerIndex: number) {
  return { project: { name: projectName }, workerIndex } as Parameters<typeof canonicalFixtureNamespace>[0];
}

describe("canonical E2E fixture namespaces", () => {
  test("are deterministic, sanitized, and bounded", () => {
    const first = canonicalFixtureNamespace(identity("Firefox 1440 / Release", 7), "CVE applicability: controls");
    const second = canonicalFixtureNamespace(identity("Firefox 1440 / Release", 7), "CVE applicability: controls");

    expect(first).toBe(second);
    expect(first).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
    expect(first.length).toBeLessThanOrEqual(64);
  });

  test("separates projects, workers, and test instances", () => {
    const values = new Set([
      canonicalFixtureNamespace(identity("chromium-1440", 1), "artifact-intelligence"),
      canonicalFixtureNamespace(identity("firefox-1440", 1), "artifact-intelligence"),
      canonicalFixtureNamespace(identity("chromium-1440", 2), "artifact-intelligence"),
      canonicalFixtureNamespace(identity("chromium-1440", 1), "cve-applicability"),
    ]);

    expect(values.size).toBe(4);
  });

  test("retains a digest when long readable names share the same prefix", () => {
    const prefix = "project-".repeat(20);
    const first = normalizeFixtureNamespace(`${prefix}alpha`);
    const second = normalizeFixtureNamespace(`${prefix}beta`);

    expect(first).not.toBe(second);
    expect(first.length).toBeLessThanOrEqual(64);
    expect(second.length).toBeLessThanOrEqual(64);
  });
});

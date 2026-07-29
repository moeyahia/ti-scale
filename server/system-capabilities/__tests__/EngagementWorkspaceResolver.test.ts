import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EngagementWorkspaceResolver } from "../EngagementWorkspaceResolver";

const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function temporaryRoot(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  temporaryRoots.push(root);
  return root;
}

describe("engagement workspace path resolution", () => {
  test("maps the legacy logical HTB path to the existing worker workspace and preserves its recorded casing", async () => {
    const runtimeRoot = await temporaryRoot("ti-scale-workspace-");
    await mkdir(join(runtimeRoot, "reapertwo", "scans"), { recursive: true });
    const resolver = new EngagementWorkspaceResolver([{
      logicalRoot: "/root/htb/boxes",
      runtimeRoot,
    }]);

    const result = await resolver.resolve("/root/htb/boxes/ReaperTwo/scans");

    expect(result).toEqual({
      schemaVersion: "ti-scale.engagement-workspace-resolution.v1",
      status: "resolved",
      code: "resolved",
      requestedPath: "/root/htb/boxes/ReaperTwo/scans",
      logicalRoot: "/root/htb/boxes",
      caseAdjusted: true,
      resolvedPath: join(runtimeRoot, "reapertwo", "scans"),
      explanation: "The engagement was resolved to the existing worker workspace using its recorded filesystem casing.",
      remediation: null,
    });
  });

  test("does not fall back from an unmapped logical root to an arbitrary host path", async () => {
    const runtimeRoot = await temporaryRoot("ti-scale-workspace-");
    const resolver = new EngagementWorkspaceResolver([{
      logicalRoot: "/root/htb/boxes",
      runtimeRoot,
    }]);

    const result = await resolver.resolve("/root/engagements/ReaperTwo");

    expect(result).toMatchObject({
      status: "unavailable",
      code: "logical_root_unmapped",
      logicalRoot: null,
      resolvedPath: null,
    });
    expect(result.remediation).toContain("reviewed logical workspace root");
  });

  test("fails closed when case-insensitive matching would select between duplicate engagement trees", async () => {
    const runtimeRoot = await temporaryRoot("ti-scale-workspace-");
    await mkdir(join(runtimeRoot, "ReaperTwo"));
    await mkdir(join(runtimeRoot, "reapertwo"));
    const resolver = new EngagementWorkspaceResolver([{
      logicalRoot: "/root/htb/boxes",
      runtimeRoot,
    }]);

    const result = await resolver.resolve("/root/htb/boxes/REAPERTWO");

    expect(result).toMatchObject({
      status: "unavailable",
      code: "case_ambiguous",
      caseAdjusted: false,
      resolvedPath: null,
    });
    expect(result.explanation).toContain("multiple case variants");
  });

  test("rejects a workspace symlink that escapes the configured runtime root", async () => {
    const runtimeRoot = await temporaryRoot("ti-scale-workspace-");
    const outside = await temporaryRoot("ti-scale-outside-");
    await symlink(outside, join(runtimeRoot, "reapertwo"));
    const resolver = new EngagementWorkspaceResolver([{
      logicalRoot: "/root/htb/boxes",
      runtimeRoot,
    }]);

    const result = await resolver.resolve("/root/htb/boxes/ReaperTwo");

    expect(result).toMatchObject({
      status: "unavailable",
      code: "path_escape",
      caseAdjusted: true,
      resolvedPath: null,
    });
    expect(result.remediation).toContain("escaping link");
  });

  test("reports a missing engagement rather than creating a second workspace tree", async () => {
    const runtimeRoot = await temporaryRoot("ti-scale-workspace-");
    const resolver = new EngagementWorkspaceResolver([{
      logicalRoot: "/root/htb/boxes",
      runtimeRoot,
    }]);

    const result = await resolver.resolve("/root/htb/boxes/ReaperTwo");

    expect(result).toMatchObject({
      status: "unavailable",
      code: "path_unavailable",
      resolvedPath: null,
    });
    expect(result.explanation).toContain("ReaperTwo");
    expect(result.remediation).toContain("reviewed workspace service");
  });
});

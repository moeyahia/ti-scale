import { afterEach, describe, expect, test } from "bun:test";
import { chmod, lstat, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ReviewedWorkspaceProvisioner } from "../ReviewedWorkspaceProvisioner";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function root(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "ti-scale-reviewed-workspace-"));
  roots.push(path);
  return path;
}

function provisioner(runtimeRoot: string): ReviewedWorkspaceProvisioner {
  return new ReviewedWorkspaceProvisioner([{
    logicalRoot: "/engagements",
    runtimeRoot,
  }]);
}

describe("reviewed autonomous workspace provisioning", () => {
  test("creates exactly one signed child with service-only ownership and permissions", async () => {
    const runtimeRoot = await root();
    const result = await provisioner(runtimeRoot).provision("/engagements/autonomous-safe-recon");

    expect(result).toMatchObject({
      status: "ready",
      code: "provisioned",
      created: true,
      runtimePath: join(runtimeRoot, "autonomous-safe-recon"),
    });
    const stat = await lstat(join(runtimeRoot, "autonomous-safe-recon"));
    expect(stat.isDirectory()).toBeTrue();
    expect(stat.isSymbolicLink()).toBeFalse();
    expect(stat.mode & 0o777).toBe(0o700);
    expect(stat.uid).toBe(process.geteuid?.() ?? process.getuid?.() ?? 0);
    expect(stat.gid).toBe(process.getegid?.() ?? process.getgid?.() ?? 0);
  });

  test("is idempotent for the same safe reviewed directory", async () => {
    const runtimeRoot = await root();
    await mkdir(join(runtimeRoot, "autonomous-safe-recon"), { mode: 0o700 });

    const result = await provisioner(runtimeRoot).provision("/engagements/autonomous-safe-recon");

    expect(result).toMatchObject({ status: "ready", code: "ready", created: false });
  });

  test("fails closed for links, case conflicts, unsafe modes, and deeper creation", async () => {
    const runtimeRoot = await root();
    const outside = await root();
    await symlink(outside, join(runtimeRoot, "linked"));
    expect(await provisioner(runtimeRoot).provision("/engagements/linked"))
      .toMatchObject({ status: "unavailable", code: "path_conflict" });

    await mkdir(join(runtimeRoot, "ReaperTwo"), { mode: 0o700 });
    expect(await provisioner(runtimeRoot).provision("/engagements/reapertwo"))
      .toMatchObject({ status: "unavailable", code: "case_conflict" });

    await mkdir(join(runtimeRoot, "shared"), { mode: 0o700 });
    await chmod(join(runtimeRoot, "shared"), 0o750);
    expect(await provisioner(runtimeRoot).provision("/engagements/shared"))
      .toMatchObject({ status: "unavailable", code: "unsafe_permissions" });

    expect(await provisioner(runtimeRoot).provision("/engagements/nested/child"))
      .toMatchObject({ status: "unavailable", code: "workspace_depth_unsupported" });
  });
});

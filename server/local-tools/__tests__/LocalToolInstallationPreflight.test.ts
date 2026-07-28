import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import {
  LocalToolCapabilityManifest,
  LocalToolInstallationPreflight,
  localToolInstallationInspectionCacheSnapshot,
} from "../index";

const TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const roots: string[] = [];

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

function document(): Record<string, any> {
  return JSON.parse(readFileSync(TEMPLATE, "utf8")) as Record<string, any>;
}

function fixture(options: { readonly hash?: string; readonly symlink?: boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-local-tool-"));
  roots.push(root);
  const executable = join(root, "tool");
  const target = join(root, "tool-real");
  const bytes = Buffer.from("reviewed local executable fixture\n", "utf8");
  writeFileSync(options.symlink ? target : executable, bytes, { mode: 0o755 });
  chmodSync(options.symlink ? target : executable, 0o755);
  if (options.symlink) symlinkSync(target, executable);
  const input = document();
  input.tools[0].executable.path = executable;
  input.tools[0].executable.expectedSha256 = options.hash
    ?? createHash("sha256").update(bytes).digest("hex");
  const manifest = new LocalToolCapabilityManifest(input);
  return { executable, manifest, toolId: input.tools[0].toolId as string };
}

describe("LocalToolInstallationPreflight", () => {
  test("attests exact bytes and no file capabilities without executing the tool", () => {
    const input = fixture();
    const receipt = new LocalToolInstallationPreflight({
      now: () => new Date("2026-07-19T12:00:00.000Z"),
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
      inspectFileCapabilities: () => ({
        state: "none",
        outputSha256: createHash("sha256").update("").digest("hex"),
      }),
    }).inspect(input.manifest, input.toolId);
    expect(receipt).toMatchObject({
      status: "ready",
      code: "ready",
      noNewPrivilegesCompatible: true,
      grantsMissionExecution: false,
      probeBoundary: {
        toolExecuted: false,
        shell: false,
        targetArgumentsSupplied: false,
        externalContact: "not_attempted",
      },
    });
    expect(receipt.observedExecutableSha256).toBe(receipt.expectedExecutableSha256);
  });

  test("reuses one bounded async hash and invalidates it when executable metadata changes", async () => {
    const input = fixture();
    const owner = process.geteuid?.() ?? process.getuid?.() ?? 0;
    const preflight = new LocalToolInstallationPreflight({
      allowedOwnerUids: [owner],
      inspectFileCapabilities: () => ({ state: "none", outputSha256: null }),
    });
    const before = localToolInstallationInspectionCacheSnapshot();
    for (let attempt = 0; attempt < 100; attempt += 1) {
      expect(await preflight.inspectAsync(input.manifest, input.toolId)).toMatchObject({
        status: "ready",
        code: "ready",
      });
    }
    const stable = localToolInstallationInspectionCacheSnapshot();
    expect(stable.hashBuilds - before.hashBuilds).toBe(1);
    expect(stable.cacheHits - before.cacheHits).toBe(99);

    const revisedBytes = Buffer.from("reviewed local executable fixture changed\n", "utf8");
    writeFileSync(input.executable, revisedBytes, { mode: 0o755 });
    chmodSync(input.executable, 0o755);
    const revisedDocument = document();
    revisedDocument.tools[0].executable.path = input.executable;
    revisedDocument.tools[0].executable.expectedSha256 = createHash("sha256")
      .update(revisedBytes).digest("hex");
    const revisedManifest = new LocalToolCapabilityManifest(revisedDocument);
    expect(await preflight.inspectAsync(revisedManifest, input.toolId)).toMatchObject({
      status: "ready",
      code: "ready",
      observedExecutableSha256: revisedDocument.tools[0].executable.expectedSha256,
    });
    const invalidated = localToolInstallationInspectionCacheSnapshot();
    expect(invalidated.hashBuilds - before.hashBuilds).toBe(2);
    expect(invalidated.cacheHits - before.cacheHits).toBe(99);
  });

  test("fails closed on Linux file capabilities under NoNewPrivileges", () => {
    const input = fixture();
    const receipt = new LocalToolInstallationPreflight({
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
      inspectFileCapabilities: () => ({ state: "present", outputSha256: "a".repeat(64) }),
    }).inspect(input.manifest, input.toolId);
    expect(receipt).toMatchObject({
      status: "unavailable",
      code: "no_new_privileges_file_capability_conflict",
      fileCapabilitiesPresent: true,
      noNewPrivilegesCompatible: false,
      grantsMissionExecution: false,
    });
  });

  test("fails closed on hash drift and never invokes the capability inspector", () => {
    const input = fixture({ hash: "0".repeat(64) });
    let inspectedCapabilities = false;
    const receipt = new LocalToolInstallationPreflight({
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
      inspectFileCapabilities: () => {
        inspectedCapabilities = true;
        return { state: "none", outputSha256: null };
      },
    }).inspect(input.manifest, input.toolId);
    expect(receipt.code).toBe("executable_hash_mismatch");
    expect(receipt.status).toBe("unavailable");
    expect(inspectedCapabilities).toBeFalse();
  });

  test("rejects a symlinked executable", () => {
    const input = fixture({ symlink: true });
    const receipt = new LocalToolInstallationPreflight({
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
      inspectFileCapabilities: () => ({ state: "none", outputSha256: null }),
    }).inspect(input.manifest, input.toolId);
    expect(receipt).toMatchObject({
      status: "unavailable",
      code: "executable_not_regular",
      observedExecutableSha256: null,
    });
  });

  test("does not relabel an operator-disabled binding as ready", () => {
    const input = fixture();
    const raw = document();
    const tool = input.manifest.resolve(input.toolId)!;
    raw.tools[0] = {
      ...raw.tools[0],
      activation: "disabled",
      activationReason: "Held for explicit review.",
      executable: {
        ...raw.tools[0].executable,
        path: tool.executable.path,
        expectedSha256: tool.executable.expectedSha256,
      },
    };
    const manifest = new LocalToolCapabilityManifest(raw);
    const receipt = new LocalToolInstallationPreflight({
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
      inspectFileCapabilities: () => ({ state: "none", outputSha256: null }),
    }).inspect(manifest, input.toolId);
    expect(receipt).toMatchObject({ status: "unavailable", code: "activation_disabled" });
  });
});

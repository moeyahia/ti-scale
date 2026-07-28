import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT,
  loadProductionLocalGuidedToolConfiguration,
} from "../LocalGuidedToolConfiguration";

const TEMPLATE_ROOT = new URL("../../../deployment/runtime-config/", import.meta.url);
const roots: string[] = [];

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "ti-scale-local-guided-config-"));
  chmodSync(value, 0o700);
  roots.push(value);
  return value;
}

function copyTemplate(directory: string, template: string, name: string) {
  const source = readFileSync(new URL(template, TEMPLATE_ROOT));
  const path = join(directory, name);
  writeFileSync(path, source, { mode: 0o600, flag: "wx" });
  return { path, sha256: createHash("sha256").update(source).digest("hex") };
}

function fixture() {
  const directory = root();
  const manifest = copyTemplate(
    directory,
    "local-tool-capabilities.v1.json",
    "capabilities.json",
  );
  const sandbox = copyTemplate(
    directory,
    "bubblewrap-probe-sandbox.v1.json",
    "sandbox.json",
  );
  const workspaces = copyTemplate(
    directory,
    "engagement-workspace-mappings.v1.json",
    "workspaces.json",
  );
  return {
    directory,
    environment: {
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.trustRoot]: directory,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestPath]: manifest.path,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestSha256]: manifest.sha256,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxPath]: sandbox.path,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxSha256]: sandbox.sha256,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsPath]: workspaces.path,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsSha256]: workspaces.sha256,
    },
  };
}

describe("local Guided tool configuration", () => {
  test("is unconfigured only when the complete reference set is absent", () => {
    expect(loadProductionLocalGuidedToolConfiguration({})).toEqual({
      status: "unconfigured",
      reason: "No complete deployment-pinned local Guided tool configuration is configured.",
    });
  });

  test("rejects a partial configuration instead of silently dropping execution gates", () => {
    expect(() => loadProductionLocalGuidedToolConfiguration({
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.trustRoot]: "/etc/ti-scale/runtime",
    })).toThrow("configuration is incomplete");
  });

  test("loads all three pinned documents without probing or granting execution", () => {
    const { environment } = fixture();
    const result = loadProductionLocalGuidedToolConfiguration(environment);
    expect(result.status).toBe("loaded");
    if (result.status !== "loaded") throw new Error("fixture did not load");
    expect(result.manifest.descriptor).toMatchObject({
      enabledToolCount: 4,
      sourceOfTruth: "reviewed-local-tool-capability-manifest",
    });
    expect(result.probeSandbox).toMatchObject({
      schemaVersion: "ti-scale.bubblewrap-probe-sandbox.v1",
      fileCapabilities: "none",
    });
    expect(result.workspaceMappings).toMatchObject({
      schemaVersion: "ti-scale.engagement-workspace-mappings.v1",
      mappings: [{
        logicalRoot: "/engagements",
        runtimeRoot: "/var/lib/ti-scale/workspaces/engagements",
      }],
    });
    expect(Object.values(result.receipts).every(
      ({ sourceSha256 }) => /^[a-f0-9]{64}$/u.test(sourceSha256),
    )).toBeTrue();
    expect(result.manifest.toRuntimeSourceManifests().tools.every(
      ({ available }) => available === false,
    )).toBeTrue();
  });

  test("rejects one drifted document without partially loading the others", () => {
    const { environment } = fixture();
    expect(() => loadProductionLocalGuidedToolConfiguration({
      ...environment,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxSha256]: "f".repeat(64),
    })).toThrow("does not match its reviewed SHA-256");
  });
});

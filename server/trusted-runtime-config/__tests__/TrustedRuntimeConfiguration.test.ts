import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import {
  ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
  RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION,
  loadTrustedEngagementWorkspaceMappings,
  loadTrustedLocalAutonomousPlanningPolicy,
  loadTrustedRuntimeSourceManifests,
  type TrustedJsonFileReference,
} from "../index";

const roots: string[] = [];
const MODEL_HASH = "a".repeat(64);

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true });
});

function root(prefix = "ti-scale-trusted-config-"): string {
  const value = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(value, 0o700);
  roots.push(value);
  return value;
}

function owners(): readonly number[] {
  const uid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  return uid === 0 ? [0] : [0, uid];
}

function writeDocument(
  trustRoot: string,
  name: string,
  value: unknown,
): TrustedJsonFileReference {
  const source = `${JSON.stringify(value, null, 2)}\n`;
  const path = join(trustRoot, name);
  writeFileSync(path, source, { mode: 0o600, flag: "wx" });
  return {
    path,
    trustRoot,
    expectedSha256: createHash("sha256").update(source).digest("hex"),
    allowedOwnerUids: owners(),
  };
}

function planningPolicy(): unknown {
  return {
    schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
    policyId: "reviewed-recon-v1",
    maximumSteps: 8,
    bindings: [{
      bindingId: "binding-active-host-discovery-v1",
      actionClassId: "active_host_discovery",
      targetKinds: ["ip", "cidr"],
      phase: "Reachability baseline",
      title: "Confirm approved target reachability",
      objective: "Determine whether the approved target is reachable",
      explanation: "The specialist performs one bounded check against the exact approved target.",
      rationale: "Confirm reachability before deeper service work.",
      successCriteria: ["An attributable result is retained"],
      reversibility: "The check makes no persistent target change.",
      riskClass: "medium",
      idempotent: false,
      destructive: false,
      agentId: "ReconScout",
      providerId: "provider-autonomous",
      modelId: "model-reviewed",
      modelConfigurationHash: MODEL_HASH,
      mcpServerId: "specialist-mcp",
      toolName: "tool-active-host-discovery",
      targetParameter: "target",
      staticParameters: { mode: "bounded" },
      capabilityIds: ["cap-recon"],
      requiredEvidenceTypeIds: ["asset_discovery_proof"],
    }],
  };
}

function manifestDocument(): unknown {
  return {
    schemaVersion: RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION,
    manifestVersion: "reviewed-recon-2026-07-19",
    manifests: {
      riskClasses: [{
        id: "risk-moderate",
        label: "Moderate active reconnaissance",
        actionClassIds: ["active_host_discovery"],
      }],
      evidenceKinds: [{
        id: "host-result",
        label: "Host discovery result",
        evidenceTypeIds: ["asset_discovery_proof"],
      }],
      capabilities: [{
        id: "cap-recon",
        label: "Bounded reconnaissance",
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: ["asset_discovery_proof"],
      }],
      tools: [{
        id: "tool-active-host-discovery",
        label: "Bounded host discovery",
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: true,
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: ["asset_discovery_proof"],
        riskClassIds: ["risk-moderate"],
        mcpServerId: "specialist-mcp",
        dependencies: [{ id: "reviewed-route", ready: true }],
      }],
      mcpServers: [{
        id: "specialist-mcp",
        label: "Specialist MCP",
        status: "healthy",
        toolIds: ["tool-active-host-discovery"],
      }],
      agents: [{
        id: "ReconScout",
        label: "Recon Scout",
        available: true,
        capabilityIds: ["cap-recon"],
        actionClassIds: ["active_host_discovery"],
        toolIds: ["tool-active-host-discovery"],
        modelRefs: [{ providerId: "provider-autonomous", modelId: "model-reviewed" }],
      }],
      providers: [{
        id: "provider-autonomous",
        authenticated: true,
        healthy: true,
        catalogObservedAt: "2026-07-19T09:00:00.000Z",
        models: [{
          id: "model-reviewed",
          displayName: "Reviewed model",
          toolCalling: true,
          structuredOutput: true,
          enforcement: "enforced_executor",
          compatibleActionClassIds: ["active_host_discovery"],
          disclosureClasses: ["public"],
          contextLimit: 128_000,
          reasoningEfforts: ["low", "medium", "high"],
        }],
      }],
    },
  };
}

describe("trusted runtime configuration files", () => {
  test("loads a deployment-pinned Autonomous policy without activating a runtime", () => {
    const trustRoot = root();
    const loaded = loadTrustedLocalAutonomousPlanningPolicy(
      writeDocument(trustRoot, "autonomous-planning-policy.json", planningPolicy()),
    );

    expect(loaded.value).toMatchObject({
      schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
      policyId: "reviewed-recon-v1",
      maximumSteps: 8,
    });
    expect(Object.isFrozen(loaded.value)).toBe(true);
    expect(Object.isFrozen(loaded.value.bindings)).toBe(true);
    expect(loaded.receipt).toMatchObject({
      schemaVersion: "ti-scale.trusted-local-file-receipt.v1",
      sourceSha256: loaded.receipt.sourceSha256,
      canonicalSha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
      mode: 0o600,
    });
    expect(loaded.receipt.sourceSha256).toHaveLength(64);
  });

  test("rejects a reviewed-file hash mismatch before parsing authority", () => {
    const trustRoot = root();
    const reference = writeDocument(trustRoot, "policy.json", planningPolicy());
    expect(() => loadTrustedLocalAutonomousPlanningPolicy({
      ...reference,
      expectedSha256: "f".repeat(64),
    })).toThrow("does not match its reviewed SHA-256");
  });

  test("rejects symlinks, writable path components, and paths outside the trusted root", () => {
    const trustRoot = root();
    const outsideRoot = root("ti-scale-untrusted-config-");
    const target = writeDocument(trustRoot, "target.json", planningPolicy());
    const symlinkPath = join(trustRoot, "linked.json");
    symlinkSync(target.path, symlinkPath);
    expect(() => loadTrustedLocalAutonomousPlanningPolicy({
      ...target,
      path: symlinkPath,
    })).toThrow("regular non-symlink file");

    chmodSync(target.path, 0o700);
    expect(() => loadTrustedLocalAutonomousPlanningPolicy(target))
      .toThrow("must be non-executable");
    chmodSync(target.path, 0o600);

    const writableDirectory = join(trustRoot, "writable");
    mkdirSync(writableDirectory, { mode: 0o700 });
    const nested = writeDocument(writableDirectory, "policy.json", planningPolicy());
    chmodSync(writableDirectory, 0o777);
    expect(() => loadTrustedLocalAutonomousPlanningPolicy({
      ...nested,
      trustRoot,
    })).toThrow("must not be group/world writable");

    const outside = writeDocument(outsideRoot, "outside.json", planningPolicy());
    expect(() => loadTrustedLocalAutonomousPlanningPolicy({
      ...outside,
      trustRoot,
    })).toThrow("must remain below its trust root");
  });

  test("loads a strict versioned runtime manifest only after registry cross-validation", () => {
    const trustRoot = root();
    const loaded = loadTrustedRuntimeSourceManifests(
      writeDocument(trustRoot, "runtime-source-manifests.json", manifestDocument()),
    );

    expect(loaded.value).toMatchObject({
      schemaVersion: RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION,
      manifestVersion: "reviewed-recon-2026-07-19",
    });
    expect(loaded.value.manifests.tools[0]).toMatchObject({
      id: "tool-active-host-discovery",
      mcpServerId: "specialist-mcp",
    });
    expect(loaded.value.manifests.providers[0]?.models[0]?.executionBoundary)
      .toBe("provider_tool_calling");
    expect(Object.isFrozen(loaded.value.manifests.tools[0])).toBe(true);
  });

  test("rejects unsupported manifest versions, extra fields, and broken cross-references", () => {
    const trustRoot = root();
    const unsupported = {
      ...(manifestDocument() as Record<string, unknown>),
      schemaVersion: "ti-scale.runtime-source-manifests.v2",
    };
    expect(() => loadTrustedRuntimeSourceManifests(
      writeDocument(trustRoot, "unsupported.json", unsupported),
    )).toThrow("Unsupported runtime source manifest schema");

    const extra = structuredClone(manifestDocument()) as {
      manifests: { tools: Array<Record<string, unknown>> };
    };
    extra.manifests.tools[0]!.command = "never accepted";
    expect(() => loadTrustedRuntimeSourceManifests(
      writeDocument(trustRoot, "extra.json", extra),
    )).toThrow("unexpected: command");

    const broken = structuredClone(manifestDocument()) as {
      manifests: { mcpServers: Array<{ toolIds: string[] }> };
    };
    broken.manifests.mcpServers[0]!.toolIds = ["unknown-tool"];
    expect(() => loadTrustedRuntimeSourceManifests(
      writeDocument(trustRoot, "broken.json", broken),
    )).toThrow("broken references");

    const unknownBoundary = structuredClone(manifestDocument()) as {
      manifests: {
        providers: Array<{
          models: Array<Record<string, unknown>>;
        }>;
      };
    };
    unknownBoundary.manifests.providers[0]!.models[0]!.executionBoundary =
      "provider_claimed_local";
    expect(() => loadTrustedRuntimeSourceManifests(
      writeDocument(trustRoot, "unknown-boundary.json", unknownBoundary),
    )).toThrow("executionBoundary is unsupported");
  });

  test("loads reviewed workspace mappings and feeds the existing fail-closed resolver", async () => {
    const trustRoot = root();
    const runtimeRoot = join(trustRoot, "workspaces");
    mkdirSync(join(runtimeRoot, "reapertwo", "scans"), { mode: 0o700, recursive: true });
    const document = {
      schemaVersion: ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
      mappingVersion: "htb-worker-v1",
      mappings: [{ logicalRoot: "/root/htb/boxes", runtimeRoot }],
    };
    const loaded = loadTrustedEngagementWorkspaceMappings(
      writeDocument(trustRoot, "workspace-mappings.json", document),
    );
    const resolver = new EngagementWorkspaceResolver(loaded.value.mappings);
    const resolution = await resolver.resolve("/root/htb/boxes/ReaperTwo/scans");

    expect(loaded.value.mappingVersion).toBe("htb-worker-v1");
    expect(resolution).toMatchObject({
      status: "resolved",
      caseAdjusted: true,
      resolvedPath: join(runtimeRoot, "reapertwo", "scans"),
    });
  });

  test("rejects broad, duplicate, and unknown workspace mapping document shapes", () => {
    const trustRoot = root();
    const broad = {
      schemaVersion: ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
      mappingVersion: "broad-v1",
      mappings: [{ logicalRoot: "/", runtimeRoot: "/" }],
    };
    expect(() => loadTrustedEngagementWorkspaceMappings(
      writeDocument(trustRoot, "broad.json", broad),
    )).toThrow("narrower than the filesystem root");

    const duplicate = {
      schemaVersion: ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
      mappingVersion: "duplicate-v1",
      mappings: [
        { logicalRoot: "/root/htb/boxes", runtimeRoot: "/srv/worker" },
        { logicalRoot: "/root/engagements", runtimeRoot: "/srv/worker" },
      ],
    };
    expect(() => loadTrustedEngagementWorkspaceMappings(
      writeDocument(trustRoot, "duplicate.json", duplicate),
    )).toThrow("runtime roots must be unique");

    const unknown = {
      schemaVersion: ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
      mappingVersion: "unknown-v1",
      mappings: [{ logicalRoot: "/root/htb/boxes", runtimeRoot: "/srv/worker", shell: true }],
    };
    expect(() => loadTrustedEngagementWorkspaceMappings(
      writeDocument(trustRoot, "unknown.json", unknown),
    )).toThrow("unexpected: shell");
  });
});

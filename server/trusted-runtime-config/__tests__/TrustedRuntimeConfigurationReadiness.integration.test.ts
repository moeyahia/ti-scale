import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
  RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION,
  projectTrustedRuntimeConfigurationReadiness,
  type TrustedJsonFileReference,
} from "../index";

const roots: string[] = [];
const MODEL_HASH = "a".repeat(64);

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "ti-scale-trusted-readiness-integration-"));
  chmodSync(value, 0o700);
  roots.push(value);
  return value;
}

function owners(): readonly number[] {
  const uid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  return uid === 0 ? [0] : [0, uid];
}

function document(
  trustRoot: string,
  name: string,
  value: unknown,
): TrustedJsonFileReference {
  const source = `${JSON.stringify(value, null, 2)}\n`;
  const path = join(trustRoot, name);
  writeFileSync(path, source, { flag: "wx", mode: 0o600 });
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

function manifests(): unknown {
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

describe("trusted runtime configuration readiness integration", () => {
  test("loads all three reviewed documents while granting no execution authority", () => {
    const trustRoot = root();
    const runtimeRoot = join(trustRoot, "workspaces");
    mkdirSync(runtimeRoot, { recursive: true, mode: 0o700 });
    const readiness = projectTrustedRuntimeConfigurationReadiness({
      planningPolicy: document(trustRoot, "planning-policy.json", planningPolicy()),
      runtimeSourceManifests: document(trustRoot, "runtime-manifests.json", manifests()),
      workspaceMappings: document(trustRoot, "workspace-mappings.json", {
        schemaVersion: ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
        mappingVersion: "worker-paths-v1",
        mappings: [{ logicalRoot: "/root/htb/boxes", runtimeRoot }],
      }),
    }, () => new Date("2026-07-19T12:30:00.000Z"));

    expect(readiness).toMatchObject({
      status: "valid",
      configured: true,
      complete: true,
      checkedAt: "2026-07-19T12:30:00.000Z",
      executionAuthorized: false,
      plannerMounted: false,
      providerExecutionMounted: false,
      specialistExecutionMounted: false,
      toolExecutionMounted: false,
      documents: {
        planningPolicy: {
          status: "valid",
          schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
          documentVersion: "reviewed-recon-v1",
        },
        runtimeSourceManifests: {
          status: "valid",
          schemaVersion: RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION,
          documentVersion: "reviewed-recon-2026-07-19",
        },
        workspaceMappings: {
          status: "valid",
          schemaVersion: ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
          documentVersion: "worker-paths-v1",
        },
      },
    });
    for (const value of Object.values(readiness.documents)) {
      expect(value.sourceSha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(value.canonicalSha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(value.byteSize).toBeGreaterThan(2);
    }

    const serialized = JSON.stringify(readiness);
    expect(serialized).not.toContain(trustRoot);
    expect(serialized).not.toContain(runtimeRoot);
    expect(serialized).not.toContain("/root/htb/boxes");
    expect(serialized).not.toContain("active_host_discovery");
    expect(serialized).not.toContain("targetParameter");
    expect(serialized).not.toContain("provider-autonomous");
    expect(serialized).not.toContain("specialist-mcp");
  });

  test("treats a partially configured document set as unavailable, not ready", () => {
    const trustRoot = root();
    const readiness = projectTrustedRuntimeConfigurationReadiness({
      planningPolicy: document(trustRoot, "planning-policy.json", planningPolicy()),
    });

    expect(readiness).toMatchObject({
      status: "unavailable",
      configured: true,
      complete: false,
      executionAuthorized: false,
      documents: {
        planningPolicy: { status: "valid" },
        runtimeSourceManifests: { status: "unconfigured" },
        workspaceMappings: { status: "unconfigured" },
      },
    });
  });
});

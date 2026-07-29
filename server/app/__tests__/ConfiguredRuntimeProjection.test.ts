import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { emptyRuntimeSourceManifests } from "../../domain";
import {
  createProductionToolBindingReadiness,
  TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
} from "../../system-capabilities";
import {
  loadProductionRuntimeManifest,
  projectConfiguredRuntimeManifest,
  RUNTIME_SOURCE_MANIFEST_ENVIRONMENT,
} from "../ConfiguredRuntimeProjection";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "ti-scale-runtime-projection-"));
  chmodSync(value, 0o700);
  roots.push(value);
  return value;
}

function manifest(overrides: Readonly<Record<string, unknown>> = {}): unknown {
  return {
    schemaVersion: "ti-scale.runtime-source-manifests.v1",
    manifestVersion: "configured-runtime-v1",
    manifests: {
      riskClasses: [{
        id: "passive-local-read",
        label: "Passive local inspection",
        actionClassIds: ["passive_intelligence_osint"],
      }],
      evidenceKinds: [],
      capabilities: [{
        id: "local-inventory",
        label: "Local runtime inventory",
        actionClassIds: ["passive_intelligence_osint"],
      }],
      tools: [{
        id: "kali:env-probe",
        label: "Local environment inspector",
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: false,
        actionClassIds: ["passive_intelligence_osint"],
        evidenceTypeIds: [],
        riskClassIds: ["passive-local-read"],
      }],
      mcpServers: [],
      agents: [{
        id: "InventorySpecialist",
        label: "Inventory Specialist",
        available: true,
        capabilityIds: ["local-inventory"],
        actionClassIds: ["passive_intelligence_osint"],
        toolIds: ["kali:env-probe"],
        modelRefs: [],
      }],
      providers: [],
      ...overrides,
    },
  };
}

function writeJson(directory: string, name: string, value: unknown): {
  path: string;
  sha256: string;
} {
  const source = `${JSON.stringify(value, null, 2)}\n`;
  const path = join(directory, name);
  writeFileSync(path, source, { mode: 0o600, flag: "wx" });
  return { path, sha256: createHash("sha256").update(source).digest("hex") };
}

function environment(directory: string, document: { path: string; sha256: string }) {
  return {
    [RUNTIME_SOURCE_MANIFEST_ENVIRONMENT.path]: document.path,
    [RUNTIME_SOURCE_MANIFEST_ENVIRONMENT.trustRoot]: directory,
    [RUNTIME_SOURCE_MANIFEST_ENVIRONMENT.expectedSha256]: document.sha256,
  };
}

function baseline(): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: false,
      delegationEnforced: false,
      noHandsCommanderEnforced: false,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: 0,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      guidedManualPlanning: {
        status: "ready",
        plannerId: "ti-scale.local-guided-manual-planner",
        executionMode: "manual_only",
        targetInteraction: "operator_only",
        providerContact: false,
        toolDispatch: false,
        reason: "Local represented manual planning is mounted.",
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
    },
    agents: [{
      id: "ti-scale.local-guided-manual-planner",
      role: "deterministic-guided-manual-planner",
      displayName: "Local Guided Manual Planner",
      status: "available",
      providerPolicy: { providerContact: false },
      toolPolicy: { execution: "denied" },
      configuration: { executionMode: "manual_only" },
      version: "guided-manual-v1",
      capabilities: [],
    }],
    mcpServers: [],
    capabilityManifests: emptyRuntimeSourceManifests(),
  };
}

describe("configured runtime projection", () => {
  test("keeps the source manifest unconfigured unless all three pinned values exist", () => {
    expect(loadProductionRuntimeManifest({})).toEqual({
      status: "unconfigured",
      reason: "No deployment-pinned runtime source manifest is configured.",
    });
    expect(() => loadProductionRuntimeManifest({
      [RUNTIME_SOURCE_MANIFEST_ENVIRONMENT.path]: "/etc/ti-scale/runtime.json",
    })).toThrow("configuration is incomplete");
  });

  test("loads exact reviewed definitions while withdrawing every live execution claim", () => {
    const directory = root();
    const document = writeJson(directory, "runtime-source-manifests.json", manifest());
    const configured = loadProductionRuntimeManifest(environment(directory, document));
    expect(configured.status).toBe("loaded");
    if (configured.status !== "loaded") throw new Error("fixture was not loaded");

    const projected = projectConfiguredRuntimeManifest(baseline(), configured);
    expect(projected.readiness).toMatchObject({
      specialistsConfigured: 0,
      actionBoundaryActive: false,
      guidedManualPlanning: { status: "ready", toolDispatch: false },
    });
    expect(projected.agents).toHaveLength(2);
    expect(projected.agents[1]).toMatchObject({
      id: "InventorySpecialist",
      status: "offline",
      lastHeartbeatAt: null,
      toolPolicy: {
        execution: "unavailable_until_exact_runtime_binding",
        liveToolAttestation: false,
      },
      configuration: {
        projectionKind: "definition_only",
        executionMounted: false,
        productRosterBindingEligible: false,
      },
    });
    expect(projected.capabilityManifests?.agents[0]).toMatchObject({
      id: "InventorySpecialist",
      available: false,
    });
    expect(projected.capabilityManifests?.tools[0]).toMatchObject({
      id: "kali:env-probe",
      available: true,
    });
  });

  test("rejects digest drift and live-adapter ID shadowing", () => {
    const directory = root();
    const document = writeJson(directory, "runtime-source-manifests.json", manifest());
    expect(() => loadProductionRuntimeManifest({
      ...environment(directory, document),
      [RUNTIME_SOURCE_MANIFEST_ENVIRONMENT.expectedSha256]: "f".repeat(64),
    })).toThrow("does not match its reviewed SHA-256");

    const collision = writeJson(directory, "runtime-source-collision.json", manifest({
      providers: [{
        id: "openrouter",
        authenticated: false,
        healthy: false,
        catalogObservedAt: "2026-07-19T00:00:00.000Z",
        models: [],
      }],
    }));
    expect(() => loadProductionRuntimeManifest(environment(directory, collision)))
      .toThrow("shadows live adapter IDs: provider:openrouter");
  });

  test("runs the exact target-free local preflight and keeps the tool unavailable without a sealed probe worker", async () => {
    const directory = root();
    const document = writeJson(directory, "runtime-source-manifests.json", manifest());
    const configured = loadProductionRuntimeManifest(environment(directory, document));
    if (configured.status !== "loaded") throw new Error("fixture was not loaded");
    const projected = projectConfiguredRuntimeManifest(baseline(), configured);
    const registry = writeJson(directory, "tool-bindings.json", {
      schemaVersion: TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
      registryVersion: "configured-runtime-v1",
      bindings: [{
        toolId: "kali:env-probe",
        executablePath: "/usr/bin/env",
        probeArguments: ["--version"],
        expectedExitCodes: [0],
        timeoutMs: 1_000,
        maximumOutputBytes: 4_096,
        ttlMs: 60_000,
      }],
    });
    const readiness = createProductionToolBindingReadiness({
      manifests: projected.capabilityManifests!,
      registryPath: registry.path,
    });
    const snapshot = await readiness.runner.startMonitoring();
    readiness.assertCompleteInitialWave(snapshot);
    try {
      expect(snapshot.accounting).toMatchObject({
        registered: 1,
        attempted: 1,
        reported: 1,
        ready: 0,
        unavailable: 1,
        complete: true,
      });
      expect(snapshot.receipts[0]).toMatchObject({
        toolId: "kali:env-probe",
        status: "unavailable",
        code: "startup_probe_isolation_unavailable",
        grantsMissionExecution: false,
        probeBoundary: {
          targetArgumentsSupplied: false,
          providerArgumentsSupplied: false,
          mcpArgumentsSupplied: false,
          networkIsolationEnforced: false,
          filesystemWriteIsolationEnforced: false,
          immutableSnapshotExecutionEnforced: false,
        },
      });
      expect(readiness.projectManifests(projected.capabilityManifests!).tools[0])
        .toMatchObject({
          id: "kali:env-probe",
          available: false,
          dependencies: expect.arrayContaining([
            { id: "local-tool-binding-readiness", ready: false },
          ]),
        });
    } finally {
      await readiness.runner.stop();
    }
  });
});

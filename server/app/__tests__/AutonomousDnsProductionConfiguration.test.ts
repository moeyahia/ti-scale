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
import { afterEach, describe, expect, test } from "bun:test";
import {
  AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS,
  createAutonomousLocalSafeReconPlanningPolicy,
} from "../../autonomous-runtime";
import {
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
} from "../../domain";
import { LocalToolCapabilityManifest } from "../../local-tools";
import {
  AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT,
  loadProductionAutonomousDnsConfiguration,
} from "../AutonomousDnsProductionConfiguration";
import {
  AUTONOMOUS_EXPLOIT_VALIDATION_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
  parseAutonomousDnsRuntimeConfiguration,
} from "../AutonomousDnsActivationCoordinator";

const TEMPLATE = new URL(
  "../../../deployment/runtime-config/autonomous-dns-local-runtime.v1.json",
  import.meta.url,
);
const ENABLED_MANIFEST = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
  import.meta.url,
);
const EXPLOIT_RUNTIME = new URL(
  "../../../deployment/runtime-config/autonomous-exploit-validation-runtime.v1.json",
  import.meta.url,
);
const CVE_CATALOG = new URL(
  "../../../deployment/runtime-config/autonomous-cve-candidate-catalog.v1.json",
  import.meta.url,
);
const EXPLOIT_SANDBOX_MANIFEST = new URL(
  "../../../deployment/exact-target-sandbox/activation-manifest.v1.json",
  import.meta.url,
);
const roots: string[] = [];
afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

function fixture(): Readonly<Record<string, string>> {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-autonomous-dns-config-"));
  chmodSync(directory, 0o700);
  roots.push(directory);
  const source = readFileSync(TEMPLATE);
  const path = join(directory, "autonomous-dns-local-runtime.v1.json");
  writeFileSync(path, source, { mode: 0o600, flag: "wx" });
  return {
    [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.trustRoot]: directory,
    [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationPath]: path,
    [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationSha256]:
      createHash("sha256").update(source).digest("hex"),
  };
}

describe("Autonomous Safe Recon production configuration", () => {
  test("is unconfigured only when the required local runtime reference is absent", () => {
    expect(loadProductionAutonomousDnsConfiguration({})).toEqual({
      status: "unconfigured",
      reason: "No complete deployment-pinned Autonomous DNS local runtime configuration is configured.",
    });
  });

  test("rejects a partial required reference and a half-configured advisory MCP pair", () => {
    expect(() => loadProductionAutonomousDnsConfiguration({
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.trustRoot]: "/etc/ti-scale/runtime",
    })).toThrow("configuration is incomplete");
    expect(() => loadProductionAutonomousDnsConfiguration({
      ...fixture(),
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.mcpConnectionPath]: "/etc/ti-scale/runtime/advisory.json",
    })).toThrow("configuration is incomplete");
    expect(() => loadProductionAutonomousDnsConfiguration({
      ...fixture(),
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxTrustRoot]:
        "/etc/ti-scale/runtime/exact-target-sandbox",
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxManifestPath]:
        "/etc/ti-scale/runtime/exact-target-sandbox/activation-manifest.v1.json",
    })).toThrow("configuration is incomplete");
  });

  test("parses the explicit versioned exploit phase without changing the assessment-only document", () => {
    const assessment = parseAutonomousDnsRuntimeConfiguration(
      JSON.parse(readFileSync(TEMPLATE, "utf8")) as unknown,
    );
    expect(assessment.exploitValidation).toBeUndefined();

    const runtime = parseAutonomousDnsRuntimeConfiguration(
      JSON.parse(readFileSync(EXPLOIT_RUNTIME, "utf8")) as unknown,
    );
    expect(runtime.exploitValidation).toEqual({
      schemaVersion:
        AUTONOMOUS_EXPLOIT_VALIDATION_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
      configurationVersion: "exact-target-script-validation-2026.07.23-v1",
      bindingId: "binding:autonomous-exact-target-exploit-validation-v1",
      agentId: runtime.specialist.id,
      providerId: runtime.provider.id,
      modelId: runtime.provider.modelId,
      modelConfigurationHash: runtime.provider.modelConfigurationHash,
      logicalWorkspace: runtime.fullTcpBaseline!.logicalWorkspace,
      successCriterion:
        "One approved evidence-matched ScriptArtifact ran inside exact-target confinement and a separate candidate-specific observer verified the expected target-state change with custody-preserved evidence; process exit and stdout do not prove success",
    });
  });

  test("loads exploit authority only from the complete root-owned manifest tuple", () => {
    const runtimeRoot = mkdtempSync(
      join(tmpdir(), "ti-scale-autonomous-exploit-runtime-"),
    );
    const sandboxRoot = mkdtempSync(
      join(tmpdir(), "ti-scale-autonomous-exploit-sandbox-"),
    );
    chmodSync(runtimeRoot, 0o700);
    chmodSync(sandboxRoot, 0o700);
    roots.push(runtimeRoot, sandboxRoot);
    const runtimeBytes = readFileSync(EXPLOIT_RUNTIME);
    const catalogBytes = readFileSync(CVE_CATALOG);
    const sandboxBytes = readFileSync(EXPLOIT_SANDBOX_MANIFEST);
    const runtimePath = join(runtimeRoot, "runtime.json");
    const catalogPath = join(runtimeRoot, "catalog.json");
    const sandboxPath = join(sandboxRoot, "activation-manifest.v1.json");
    writeFileSync(runtimePath, runtimeBytes, { mode: 0o600, flag: "wx" });
    writeFileSync(catalogPath, catalogBytes, { mode: 0o600, flag: "wx" });
    writeFileSync(sandboxPath, sandboxBytes, { mode: 0o600, flag: "wx" });
    const environment = {
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.trustRoot]: runtimeRoot,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationPath]:
        runtimePath,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationSha256]:
        createHash("sha256").update(runtimeBytes).digest("hex"),
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.cveCandidateCatalogPath]:
        catalogPath,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.cveCandidateCatalogSha256]:
        createHash("sha256").update(catalogBytes).digest("hex"),
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxTrustRoot]:
        sandboxRoot,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxManifestPath]:
        sandboxPath,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxManifestSha256]:
        createHash("sha256").update(sandboxBytes).digest("hex"),
    };
    const result = loadProductionAutonomousDnsConfiguration(environment);
    expect(result.status).toBe("loaded");
    if (result.status !== "loaded") throw new Error("exploit runtime did not load");
    expect(result.exploitSandboxManifest?.receipt.ownerUid).toBe(0);
    expect(result.exploitSandboxManifest?.value.boundary).toMatchObject({
      exactIpTargets: true,
      targetPortConfinement: false,
      publicProvider: false,
      credentialTransport: false,
    });
  });

  test("loads the deployment-pinned DNS, ping, and bounded Nmap route with no MCP configured", () => {
    const result = loadProductionAutonomousDnsConfiguration(fixture());
    expect(result.status).toBe("loaded");
    if (result.status !== "loaded") throw new Error("local Autonomous DNS fixture did not load");
    expect(result.runtime.value).toMatchObject({
      configurationVersion: "autonomous-safe-recon-local-2026.07.20-v2",
      localProcess: { adapterId: AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID },
      dns: {
        policyId: "reviewed-autonomous-local-safe-recon-v2",
        logicalWorkspace: "/engagements/autonomous-safe-recon",
        recordType: "A",
      },
      ipRecon: {
        policyId: "reviewed-autonomous-local-safe-recon-v2",
        logicalWorkspace: "/engagements/autonomous-safe-recon",
        livenessSuccessCriterion: AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
        serviceScanSuccessCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
      },
    });
    expect(result.runtime.value.ipRecon?.ports).toEqual([...AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS]);
    expect(result.runtime.value.ipRecon?.agentId).toBe(result.runtime.value.dns.agentId);
    expect(result.runtime.value.ipRecon?.providerId).toBe(result.runtime.value.dns.providerId);
    expect(result.runtime.value.ipRecon?.modelConfigurationHash)
      .toBe(result.runtime.value.dns.modelConfigurationHash);
    const manifest = new LocalToolCapabilityManifest(
      JSON.parse(readFileSync(ENABLED_MANIFEST, "utf8")),
    );
    const policy = createAutonomousLocalSafeReconPlanningPolicy(
      result.runtime.value.dns,
      result.runtime.value.ipRecon!,
      manifest,
    );
    expect(policy.maximumSteps).toBe(3);
    expect(policy.bindings.every((binding) =>
      "executionBinding" in binding && binding.executionBinding === "reviewed_local_process"))
      .toBeTrue();
    expect(policy.bindings.map((binding) =>
      "toolId" in binding ? binding.toolId : `mcp:${binding.toolName}`)).toEqual([
      "kali:host-dns-query",
      "kali:ping-host-liveness",
      "kali:nmap-tcp-connect-service-scan",
    ]);
    expect(result.runtime.value.dns.mcpServerId).toBeUndefined();
    expect(result.runtime.value.mcp).toBeUndefined();
    expect(result.mcpConnection).toBeUndefined();
    expect(result.runtime.receipt.sourceSha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  test("rejects source drift before parsing or activation", () => {
    expect(() => loadProductionAutonomousDnsConfiguration({
      ...fixture(),
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationSha256]: "f".repeat(64),
    })).toThrow("does not match its reviewed SHA-256");
  });
});

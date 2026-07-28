import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID,
  AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_BINDING_ID,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_POLICY_SCHEMA_VERSION,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID,
  AUTONOMOUS_VULNERABILITY_MAX_ORIGINS,
  AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_ID,
  AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_SHA256,
  AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
  AUTONOMOUS_WHATWEB_TOOL_ID,
  LocalAutonomousContractPlanner,
  LocalVerifiedEvidenceOutcomeEvaluator,
  createAutonomousFullTcpBaselineManifest,
  createAutonomousGeneralSafeReconPlanningPolicy,
} from "../../../server/autonomous-runtime";
import {
  cveCandidateCatalogSnapshotSha256,
  parsePinnedLocalCveCandidateCatalogDocument,
} from "../../../server/cve-intelligence";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
  AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_SUCCESS_CRITERION,
  AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
} from "../../../server/domain";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";
import {
  parseLocalToolCapabilityManifestDocument,
} from "../../../server/local-tools";
import { digestCanonicalJson } from "../../../server/mcp";
import {
  attestLocalDeterministicAutonomousDnsProvider,
  loadTrustedAutonomousDnsRuntimeConfiguration,
  parseAutonomousDnsRuntimeConfiguration,
} from "../../../server/app/AutonomousDnsActivationCoordinator";
import {
  AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT,
  loadProductionAutonomousDnsConfiguration,
} from "../../../server/app/AutonomousDnsProductionConfiguration";
import {
  LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT,
  REVIEWED_WEB_ASSESSMENT_CONFIGURATION_ENVIRONMENT,
  loadProductionLocalGuidedToolConfiguration,
} from "../../../server/app/LocalGuidedToolConfiguration";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_BINDING_ID,
  AUTONOMOUS_CVE_CANDIDATE_CATALOG_NAME,
  AUTONOMOUS_HTTP_METADATA_BINDING_ID,
  AUTONOMOUS_WHATWEB_FINGERPRINT_BINDING_ID,
  FULL_TCP_ACTIVATION_HASH_FRAGMENT_NAME,
  FULL_TCP_ACTIVATION_MANIFEST_NAME,
  FULL_TCP_ACTIVATION_RUNTIME_NAME,
  generateFullTcpSafeReconActivationDocuments,
} from "../FullTcpSafeReconActivationDocuments";

const REPOSITORY_ROOT = join(import.meta.dir, "../../..");
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function hash(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function fixture(): Readonly<{
  root: string;
  manifest: string;
  runtime: string;
  sandbox: string;
  workspaces: string;
  output: string;
  manifestBytes: Buffer;
  runtimeBytes: Buffer;
  sandboxBytes: Buffer;
  workspaceBytes: Buffer;
}> {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-full-tcp-activation-docs-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const manifest = join(root, "trusted-manifest.json");
  const runtime = join(root, "trusted-runtime.json");
  const sandbox = join(root, "sandbox.json");
  const workspaces = join(root, "workspaces.json");
  copyFileSync(
    join(REPOSITORY_ROOT, "deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json"),
    manifest,
  );
  copyFileSync(
    join(REPOSITORY_ROOT, "deployment/runtime-config/autonomous-dns-local-runtime.v1.json"),
    runtime,
  );
  copyFileSync(
    join(REPOSITORY_ROOT, "deployment/runtime-config/bubblewrap-probe-sandbox.v1.json"),
    sandbox,
  );
  copyFileSync(
    join(REPOSITORY_ROOT, "deployment/runtime-config/engagement-workspace-mappings.v1.json"),
    workspaces,
  );
  chmodSync(manifest, 0o600);
  chmodSync(runtime, 0o600);
  chmodSync(sandbox, 0o600);
  chmodSync(workspaces, 0o600);
  return {
    root,
    manifest,
    runtime,
    sandbox,
    workspaces,
    output: join(root, "generated"),
    manifestBytes: readFileSync(manifest),
    runtimeBytes: readFileSync(runtime),
    sandboxBytes: readFileSync(sandbox),
    workspaceBytes: readFileSync(workspaces),
  };
}

function reference(path: string, bytes: Buffer, maximumBytes: number) {
  return {
    path,
    trustRoot: join(path, ".."),
    expectedSha256: hash(bytes),
    allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
    maximumBytes,
  } as const;
}

function toolHash(value: unknown): string {
  return digestCanonicalJson(value, { maxBytes: 128 * 1_024, maxDepth: 16 }).sha256;
}

describe("FullTcpSafeReconActivationDocuments", () => {
  test("writes only a new explicit directory with exact phase tools, preserved DNS/IP policy, and activation hashes", async () => {
    const setup = fixture();
    const sourceManifest = parseLocalToolCapabilityManifestDocument(JSON.parse(
      setup.manifestBytes.toString("utf8"),
    ) as unknown);
    const sourceRuntime = parseAutonomousDnsRuntimeConfiguration(JSON.parse(
      setup.runtimeBytes.toString("utf8"),
    ) as unknown);

    const result = await generateFullTcpSafeReconActivationDocuments({
      sourceManifest: reference(setup.manifest, setup.manifestBytes, 2 * 1_024 * 1_024),
      sourceRuntime: reference(setup.runtime, setup.runtimeBytes, 256 * 1_024),
      outputDirectory: setup.output,
    });

    expect(readdirSync(setup.output).sort()).toEqual([
      FULL_TCP_ACTIVATION_HASH_FRAGMENT_NAME,
      FULL_TCP_ACTIVATION_RUNTIME_NAME,
      FULL_TCP_ACTIVATION_MANIFEST_NAME,
    ].sort());
    expect(readFileSync(setup.manifest)).toEqual(setup.manifestBytes);
    expect(readFileSync(setup.runtime)).toEqual(setup.runtimeBytes);

    const manifestBytes = readFileSync(result.generated.manifest.path);
    const runtimeBytes = readFileSync(result.generated.runtime.path);
    const manifest = parseLocalToolCapabilityManifestDocument(JSON.parse(
      manifestBytes.toString("utf8"),
    ) as unknown);
    const runtime = parseAutonomousDnsRuntimeConfiguration(JSON.parse(
      runtimeBytes.toString("utf8"),
    ) as unknown);
    expect(manifest.tools).toHaveLength(sourceManifest.tools.length + 3);
    expect(manifest.tools.some(({ toolId }) => toolId === AUTONOMOUS_HTTP_METADATA_TOOL_ID))
      .toBeTrue();
    expect(manifest.tools.some(({ toolId }) => toolId === AUTONOMOUS_WHATWEB_TOOL_ID))
      .toBeFalse();
    expect(runtime.dns).toEqual(sourceRuntime.dns);
    expect(runtime.ipRecon).toEqual(sourceRuntime.ipRecon);
    expect(runtime.localProcess.adapterId).toBe(AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID);
    expect(runtime.fullTcpBaseline).toEqual({
      policyId: sourceRuntime.dns.policyId,
      bindingId: "binding:autonomous-full-tcp-baseline-v1",
      agentId: sourceRuntime.dns.agentId,
      providerId: sourceRuntime.dns.providerId,
      modelId: sourceRuntime.dns.modelId,
      modelConfigurationHash: sourceRuntime.dns.modelConfigurationHash,
      logicalWorkspace: sourceRuntime.ipRecon!.logicalWorkspace,
      successCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
    });
    expect(runtime.webSurface).toEqual({
      policyId: sourceRuntime.dns.policyId,
      httpMetadataBindingId: AUTONOMOUS_HTTP_METADATA_BINDING_ID,
      whatwebBindingId: AUTONOMOUS_WHATWEB_FINGERPRINT_BINDING_ID,
      endpointDiscoveryBindingId: AUTONOMOUS_ENDPOINT_DISCOVERY_BINDING_ID,
      agentId: sourceRuntime.dns.agentId,
      providerId: sourceRuntime.dns.providerId,
      modelId: sourceRuntime.dns.modelId,
      modelConfigurationHash: sourceRuntime.dns.modelConfigurationHash,
      logicalWorkspace: sourceRuntime.ipRecon!.logicalWorkspace,
      maximumOrigins: AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
      httpMetadataSuccessCriterion: AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
      whatwebSuccessCriterion: AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
      endpointDiscoverySuccessCriterion: AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
    });
    expect(runtime.vulnerabilityAssessment).toEqual({
      schemaVersion: AUTONOMOUS_VULNERABILITY_ASSESSMENT_POLICY_SCHEMA_VERSION,
      policyId: sourceRuntime.dns.policyId,
      bindingId: AUTONOMOUS_VULNERABILITY_ASSESSMENT_BINDING_ID,
      agentId: sourceRuntime.dns.agentId,
      providerId: sourceRuntime.dns.providerId,
      modelId: sourceRuntime.dns.modelId,
      modelConfigurationHash: sourceRuntime.dns.modelConfigurationHash,
      logicalWorkspace: sourceRuntime.ipRecon!.logicalWorkspace,
      maximumOrigins: AUTONOMOUS_VULNERABILITY_MAX_ORIGINS,
      templatePackId: AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_ID,
      templatePackSha256: AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_SHA256,
      successCriterion: AUTONOMOUS_VULNERABILITY_ASSESSMENT_SUCCESS_CRITERION,
    });

    const exactPhaseTools = createAutonomousFullTcpBaselineManifest().list().map((tool) => {
      const { bindingSha256: _bindingSha256, ...document } = tool;
      return document;
    });
    for (const expected of exactPhaseTools) {
      const actual = manifest.tools.find(({ toolId }) => toolId === expected.toolId);
      expect(actual).toBeDefined();
      expect(toolHash(actual)).toBe(toolHash(expected));
    }
    expect(result.phaseToolIds).toEqual([
      AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
      AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    ]);
    expect(result.webToolIds).toEqual([
      AUTONOMOUS_HTTP_METADATA_TOOL_ID,
      AUTONOMOUS_WHATWEB_TOOL_ID,
      AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
    ]);
    expect(result.vulnerabilityToolId)
      .toBe(AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID);
    expect(result.plannerBindingIds).toEqual([
      sourceRuntime.dns.bindingId,
      sourceRuntime.ipRecon!.livenessBindingId,
      "binding:autonomous-full-tcp-baseline-v1",
      AUTONOMOUS_HTTP_METADATA_BINDING_ID,
      AUTONOMOUS_WHATWEB_FINGERPRINT_BINDING_ID,
      AUTONOMOUS_ENDPOINT_DISCOVERY_BINDING_ID,
      AUTONOMOUS_VULNERABILITY_ASSESSMENT_BINDING_ID,
    ]);
    expect(result.generated.manifest.sha256).toBe(hash(manifestBytes));
    expect(result.generated.runtime.sha256).toBe(hash(runtimeBytes));
    expect(readFileSync(result.generated.activationHashFragment.path, "utf8")).toBe([
      `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256=${hash(manifestBytes)}`,
      `TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_SHA256=${hash(runtimeBytes)}`,
      "",
    ].join("\n"));

    const production = loadProductionLocalGuidedToolConfiguration({
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.trustRoot]: setup.root,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestPath]: result.generated.manifest.path,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestSha256]: result.generated.manifest.sha256,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxPath]: setup.sandbox,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxSha256]: hash(setup.sandboxBytes),
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsPath]: setup.workspaces,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsSha256]: hash(setup.workspaceBytes),
      [REVIEWED_WEB_ASSESSMENT_CONFIGURATION_ENVIRONMENT]: "true",
    });
    expect(production.status).toBe("loaded");
    if (production.status !== "loaded") throw new Error("production manifest did not load");
    expect(production.webAssessmentIncluded).toBeTrue();
    expect(production.manifest.resolve(AUTONOMOUS_HTTP_METADATA_TOOL_ID)).toBeDefined();
    expect(production.manifest.resolve(AUTONOMOUS_WHATWEB_TOOL_ID)).toBeDefined();
    expect(production.manifest.resolve(AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID)).toBeDefined();
    expect(production.manifest.resolve(AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID))
      .toBeDefined();
    expect(new Set(production.manifest.list().map(({ toolId }) => toolId)).size)
      .toBe(production.manifest.list().length);
  });

  test("attests all seven exact planner bindings and rejects a web runtime mounted with only the three pre-web bindings", async () => {
    const setup = fixture();
    const result = await generateFullTcpSafeReconActivationDocuments({
      sourceManifest: reference(setup.manifest, setup.manifestBytes, 2 * 1_024 * 1_024),
      sourceRuntime: reference(setup.runtime, setup.runtimeBytes, 256 * 1_024),
      outputDirectory: setup.output,
    });
    const manifestBytes = readFileSync(result.generated.manifest.path);
    const runtimeBytes = readFileSync(result.generated.runtime.path);
    const manifest = loadProductionLocalGuidedToolConfiguration({
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.trustRoot]: setup.root,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestPath]: result.generated.manifest.path,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestSha256]: result.generated.manifest.sha256,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxPath]: setup.sandbox,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxSha256]: hash(setup.sandboxBytes),
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsPath]: setup.workspaces,
      [LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsSha256]: hash(setup.workspaceBytes),
      [REVIEWED_WEB_ASSESSMENT_CONFIGURATION_ENVIRONMENT]: "true",
    });
    expect(manifest.status).toBe("loaded");
    if (manifest.status !== "loaded") throw new Error("production manifest did not load");
    const configuration = loadTrustedAutonomousDnsRuntimeConfiguration(reference(
      result.generated.runtime.path,
      runtimeBytes,
      256 * 1_024,
    ));
    const runtime = configuration.value;
    if (!runtime.ipRecon || !runtime.fullTcpBaseline || !runtime.webSurface) {
      throw new Error("generated six-binding runtime is incomplete");
    }
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const exactPlanner = new LocalAutonomousContractPlanner({
      database,
      policy: createAutonomousGeneralSafeReconPlanningPolicy(
        runtime.dns,
        runtime.ipRecon,
        runtime.fullTcpBaseline,
        manifest.manifest,
        runtime.webSurface,
        undefined,
        runtime.vulnerabilityAssessment,
      ),
      readRuntimeProjection: () => { throw new Error("not used during attestation"); },
    });
    const preWebPlanner = new LocalAutonomousContractPlanner({
      database,
      policy: createAutonomousGeneralSafeReconPlanningPolicy(
        runtime.dns,
        runtime.ipRecon,
        runtime.fullTcpBaseline,
        manifest.manifest,
      ),
      readRuntimeProjection: () => { throw new Error("not used during attestation"); },
    });
    const evaluator = new LocalVerifiedEvidenceOutcomeEvaluator(database);
    const receipt = attestLocalDeterministicAutonomousDnsProvider({
      configuration,
      planner: exactPlanner,
      evaluator,
      now: new Date("2026-07-22T20:00:00.000Z"),
    });
    expect(exactPlanner.localPlanningBoundary.bindings.map(({ bindingId }) => bindingId))
      .toEqual([...result.plannerBindingIds]);
    expect(receipt.boundary).toMatchObject({
      providerContact: false,
      toolDispatch: false,
      exactTokenUsage: 0,
      exactCostUsd: 0,
    });
    expect(() => attestLocalDeterministicAutonomousDnsProvider({
      configuration,
      planner: preWebPlanner,
      evaluator,
      now: new Date("2026-07-22T20:00:00.000Z"),
    })).toThrow("do not match the trusted policy");
    database.close();
  });

  test("stages a pinned local CVE catalogue before the eighth bounded assessment binding with NVD disabled", async () => {
    const setup = fixture();
    const catalogPath = join(setup.root, "trusted-cve-catalog.json");
    const catalogDocument = {
      schemaVersion: "ti-scale.authoritative-cve-candidate-catalog.v1",
      catalogId: "catalog:activation-doc-fixture",
      catalogVersion: "activation-doc-fixture-v1",
      generatedAt: "2026-07-22T11:00:00.000Z",
      candidates: [{
        cveId: "CVE-2026-12345",
        title: "Fixture Server bounded parsing issue",
        component: { product: "Fixture Server" },
        affectedRanges: [{
          id: "affected-1.2",
          scheme: "semver",
          lower: { version: "1.2.0", inclusive: true },
          upper: { version: "1.2.5", inclusive: false },
        }],
        sources: [{
          kind: "nvd",
          authority: "NIST National Vulnerability Database",
          recordUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
          retrievedAt: "2026-07-22T11:00:00.000Z",
          sourceVersion: "NVD API 2.0 fixture snapshot",
          contentSha256: "a".repeat(64),
          retrievalReceiptId: "receipt:activation-doc-cve",
          retrievalReceiptSha256: "b".repeat(64),
        }],
      }],
    };
    writeFileSync(catalogPath, `${JSON.stringify(catalogDocument, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    const catalogBytes = readFileSync(catalogPath);
    const result = await generateFullTcpSafeReconActivationDocuments({
      sourceManifest: reference(setup.manifest, setup.manifestBytes, 2 * 1_024 * 1_024),
      sourceRuntime: reference(setup.runtime, setup.runtimeBytes, 256 * 1_024),
      sourceCveCandidateCatalog: reference(catalogPath, catalogBytes, 8 * 1_024 * 1_024),
      maximumCveCandidatesPerProduct: 10,
      outputDirectory: setup.output,
    });

    expect(readdirSync(setup.output)).toContain(AUTONOMOUS_CVE_CANDIDATE_CATALOG_NAME);
    expect(result.generated.cveCandidateCatalog).toBeDefined();
    const runtime = parseAutonomousDnsRuntimeConfiguration(JSON.parse(readFileSync(
      result.generated.runtime.path,
      "utf8",
    )) as unknown);
    const catalog = parsePinnedLocalCveCandidateCatalogDocument(JSON.parse(readFileSync(
      result.generated.cveCandidateCatalog!.path,
      "utf8",
    )) as unknown);
    expect(runtime.cveApplicability).toEqual({
      policyId: runtime.dns.policyId,
      bindingId: AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID,
      agentId: runtime.dns.agentId,
      providerId: runtime.dns.providerId,
      modelId: runtime.dns.modelId,
      modelConfigurationHash: runtime.dns.modelConfigurationHash,
      catalogId: catalog.catalogId,
      catalogSnapshotSha256: cveCandidateCatalogSnapshotSha256(catalog),
      maximumCandidatesPerProduct: 10,
      nvdEnrichment: "disabled",
      successCriterion: AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION,
    });
    expect(result.plannerBindingIds.at(-2)).toBe(AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID);
    expect(result.plannerBindingIds.at(-1))
      .toBe(AUTONOMOUS_VULNERABILITY_ASSESSMENT_BINDING_ID);
    expect(result.activationEnvironmentValues)
      .toHaveProperty("TI_SCALE_AUTONOMOUS_CVE_CANDIDATE_CATALOG_SHA256");
    expect(readFileSync(result.generated.activationHashFragment.path, "utf8"))
      .toContain("TI_SCALE_AUTONOMOUS_CVE_CANDIDATE_CATALOG_SHA256=");

    const production = loadProductionAutonomousDnsConfiguration({
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.trustRoot]: setup.root,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationPath]:
        result.generated.runtime.path,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationSha256]:
        result.generated.runtime.sha256,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.cveCandidateCatalogPath]:
        result.generated.cveCandidateCatalog!.path,
      [AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.cveCandidateCatalogSha256]:
        result.generated.cveCandidateCatalog!.sha256,
    });
    expect(production.status).toBe("loaded");
    if (production.status !== "loaded") throw new Error("CVE production config did not load");
    expect(production.cveCandidateCatalog?.catalog.catalogId).toBe(catalog.catalogId);
    expect(production.cveCandidateCatalog?.catalog.catalogSnapshotSha256)
      .toBe(runtime.cveApplicability!.catalogSnapshotSha256);
    expect(result.plannerBindingIds).toContain(AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID);
    expect(result.plannerBindingIds).toHaveLength(8);
    expect(result.plannerBindingIds).not.toContain(AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE);
  });

  test("rejects an untrusted source hash before creating output", async () => {
    const setup = fixture();
    await expect(generateFullTcpSafeReconActivationDocuments({
      sourceManifest: {
        ...reference(setup.manifest, setup.manifestBytes, 2 * 1_024 * 1_024),
        expectedSha256: "0".repeat(64),
      },
      sourceRuntime: reference(setup.runtime, setup.runtimeBytes, 256 * 1_024),
      outputDirectory: setup.output,
    })).rejects.toThrow("does not match its reviewed SHA-256");
    expect(existsSync(setup.output)).toBeFalse();
  });

  test("refuses /etc and refuses to overwrite an existing output directory", async () => {
    const setup = fixture();
    const input = {
      sourceManifest: reference(setup.manifest, setup.manifestBytes, 2 * 1_024 * 1_024),
      sourceRuntime: reference(setup.runtime, setup.runtimeBytes, 256 * 1_024),
    } as const;
    await expect(generateFullTcpSafeReconActivationDocuments({
      ...input,
      outputDirectory: "/etc/ti-scale/generated-full-tcp-test",
    })).rejects.toThrow("never writes below /etc");
    await Bun.write(setup.output, "not-a-directory");
    await expect(generateFullTcpSafeReconActivationDocuments({
      ...input,
      outputDirectory: setup.output,
    })).rejects.toThrow("must not already exist");
  });
});

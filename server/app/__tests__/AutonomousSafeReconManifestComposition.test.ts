import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES,
  AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_EVIDENCE_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_POLICY_SCHEMA_VERSION,
  AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_ID,
  AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_SHA256,
  AUTHORITATIVE_CVE_CATALOG_COMPOSITION_SCHEMA_VERSION,
  AutonomousReusableExploitCandidateMaterializer,
  CandidateSpecificIndependentExploitOutcomeVerifier,
  autonomousExploitOutcomeObserverCompositionReceiptValid,
  autonomousReusableExploitMaterializerCompositionReceiptValid,
  composeAutonomousVulnerabilityAssessmentManifest,
  createAutonomousFullTcpBaselineManifest,
  exploitOutcomeObserverSpecRegistrySha256,
} from "../../autonomous-runtime";
import {
  BrainContextService,
} from "../../brain-runtime";
import {
  createDatabaseConnection,
  migrateDatabase,
} from "../../db";
import { MissionIntakeService } from "../../intake";
import type { ExactTargetSandboxAttestation } from "../../exploit-sandbox";
import {
  buildRuntimeCapabilityProjection,
  createRuntimeAdapterAttestation,
} from "../../domain";
import {
  LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
  LocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
  type LocalToolActivationReceipt,
} from "../../local-tools";
import { composeReviewedWebAssessmentLocalManifest } from "../../web-assessment-tools";
import { digestCanonicalJson } from "../../mcp";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { FileScriptSourceStore } from "../../script-artifacts";
import {
  composeMultiToolManifests,
  requiredAutonomousSafeReconActionClassIds,
  type AutonomousDnsRuntimeConfiguration,
  type LocalDeterministicProviderAttestation,
} from "../AutonomousDnsActivationCoordinator";

const NOW = new Date("2026-07-23T05:00:00.000Z");
const POLICY_ID = "reviewed-autonomous-local-safe-recon-v2";
const AGENT_ID = "specialist:autonomous-safe-recon";
const PROVIDER_ID = "provider:local-deterministic-safe-recon";
const MODEL_ID = "policy:local-safe-recon-v2";
const MODEL_CONFIGURATION_HASH = "a".repeat(64);
const WORKSPACE = "/engagements/autonomous-safe-recon";

function productionShapedManifest(): LocalToolCapabilityManifest {
  const base = parseLocalToolCapabilityManifestDocument(JSON.parse(readFileSync(
    new URL(
      "../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
      import.meta.url,
    ),
    "utf8",
  )) as unknown);
  const fullTcp = createAutonomousFullTcpBaselineManifest().list()
    .map(({ bindingSha256: _bindingSha256, ...tool }) => tool);
  const withFullTcp = new LocalToolCapabilityManifest({
    ...base,
    manifestVersion: "autonomous-vulnerability-join-test",
    tools: [...base.tools, ...fullTcp],
  });
  return composeAutonomousVulnerabilityAssessmentManifest(
    composeReviewedWebAssessmentLocalManifest(withFullTcp),
  );
}

function activationReceipt(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
): LocalToolActivationReceipt {
  const tool = manifest.resolve(toolId)!;
  return Object.freeze({
    schemaVersion: LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
    manifestSha256: manifest.descriptor.manifestSha256,
    toolId,
    bindingSha256: tool.bindingSha256,
    preflightBindingSha256: "b".repeat(64),
    executableSha256: tool.executable.expectedSha256,
    installationReady: true,
    isolatedProbeReady: true,
    invocationAdapterReady: true,
    workspaceConfinementReady: true,
    resultSinkReady: true,
    cancellationReady: true,
    observedAt: new Date(NOW.getTime() - 1_000).toISOString(),
    expiresAt: new Date(NOW.getTime() + 59_000).toISOString(),
  });
}

function configuration(): AutonomousDnsRuntimeConfiguration {
  return Object.freeze({
    schemaVersion: "ti-scale.autonomous-dns-runtime-configuration.v1",
    configurationVersion: "autonomous-vulnerability-join-test",
    dns: Object.freeze({
      policyId: POLICY_ID,
      bindingId: "binding-autonomous-dns-a-v2",
      agentId: AGENT_ID,
      providerId: PROVIDER_ID,
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      logicalWorkspace: WORKSPACE,
      recordType: "A",
      successCriterion: "The exact DNS A query has one verified result for the authorized domain",
    }),
    ipRecon: Object.freeze({
      policyId: POLICY_ID,
      livenessBindingId: "binding-autonomous-ip-liveness-v1",
      serviceScanBindingId: "binding-autonomous-ip-services-v1",
      agentId: AGENT_ID,
      providerId: PROVIDER_ID,
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      logicalWorkspace: WORKSPACE,
      ports: Object.freeze([22, 80, 443]),
      livenessSuccessCriterion:
        "The exact approved host has one verified bounded liveness result",
      serviceScanSuccessCriterion:
        "The exact approved host has one verified result for the reviewed TCP port set",
    }),
    fullTcpBaseline: Object.freeze({
      policyId: POLICY_ID,
      bindingId: "binding:autonomous-full-tcp-baseline-v1",
      agentId: AGENT_ID,
      providerId: PROVIDER_ID,
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      logicalWorkspace: WORKSPACE,
      successCriterion:
        "The exact approved host has one verified result for the reviewed TCP port set",
    }),
    webSurface: Object.freeze({
      policyId: POLICY_ID,
      httpMetadataBindingId: "binding:autonomous-http-metadata-v1",
      whatwebBindingId: "binding:autonomous-whatweb-fingerprint-v1",
      endpointDiscoveryBindingId: "binding:autonomous-endpoint-discovery-v1",
      agentId: AGENT_ID,
      providerId: PROVIDER_ID,
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      logicalWorkspace: WORKSPACE,
      maximumOrigins: 16,
      httpMetadataSuccessCriterion:
        "Every HTTP origin derived from the verified TCP baseline has one verified bounded metadata result",
      whatwebSuccessCriterion:
        "Every responding derived HTTP origin has one verified bounded technology fingerprint result",
      endpointDiscoverySuccessCriterion:
        "Every responding derived HTTP origin has one verified bounded endpoint-discovery result",
    }),
    cveApplicability: Object.freeze({
      policyId: POLICY_ID,
      bindingId: "binding:autonomous-cve-applicability-v1",
      agentId: AGENT_ID,
      providerId: PROVIDER_ID,
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      catalogId: "catalog:reviewed-local-cve-candidates",
      catalogSnapshotSha256: "c".repeat(64),
      maximumCandidatesPerProduct: 25,
      nvdEnrichment: "disabled",
      successCriterion:
        "Every verified service product/version observation has one conservative, authoritative-source-backed CVE applicability assessment",
    }),
    vulnerabilityAssessment: Object.freeze({
      schemaVersion: AUTONOMOUS_VULNERABILITY_ASSESSMENT_POLICY_SCHEMA_VERSION,
      policyId: POLICY_ID,
      bindingId: "binding:autonomous-nuclei-safe-http-assessment-v1",
      agentId: AGENT_ID,
      providerId: PROVIDER_ID,
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      logicalWorkspace: WORKSPACE,
      maximumOrigins: 16,
      templatePackId: AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_ID,
      templatePackSha256: AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_SHA256,
      successCriterion:
        "Every responding HTTP origin derived from verified current-run evidence has one completed bounded read-only vulnerability and configuration assessment",
    }),
    localProcess: Object.freeze({ adapterId: "ti-scale:autonomous-general-safe-recon" }),
    specialist: Object.freeze({
      id: AGENT_ID,
      label: "Autonomous Safe Recon specialist",
      workerId: "worker:autonomous-safe-recon-local-1",
      version: "2.0.0",
      heartbeatTtlMs: 60_000,
    }),
    provider: Object.freeze({
      id: PROVIDER_ID,
      label: "Local deterministic Safe Recon policy",
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      policyVersion: "2.0.0",
      attestationTtlMs: 60_000,
    }),
  });
}

function providerAttestation(): LocalDeterministicProviderAttestation {
  return Object.freeze({
    schemaVersion: "ti-scale.local-deterministic-provider-attestation.v1",
    providerId: PROVIDER_ID,
    modelId: MODEL_ID,
    modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    configurationSha256: "d".repeat(64),
    policyHash: "e".repeat(64),
    plannerContractSha256: "f".repeat(64),
    evaluatorContractSha256: "1".repeat(64),
    boundary: Object.freeze({
      providerContact: false,
      providerCredentials: false,
      toolDeclarations: false,
      toolDispatch: false,
      deterministicPlanning: true,
      verifiedEvidenceEvaluation: true,
      exactTokenUsage: 0,
      exactCostUsd: 0,
    }),
    attestedAt: NOW.toISOString(),
    expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
    receiptSha256: "2".repeat(64),
  });
}

function cveRuntimeComposition(overrides: Readonly<{
  catalogId?: string;
  catalogSnapshotSha256?: string;
  nvd?: ReturnType<typeof nvdCompositionReceipt>;
}> = {}) {
  const config = configuration().cveApplicability!;
  const unsigned = Object.freeze({
    schemaVersion: AUTHORITATIVE_CVE_CATALOG_COMPOSITION_SCHEMA_VERSION,
    catalogId: overrides.catalogId ?? config.catalogId,
    catalogSnapshotSha256:
      overrides.catalogSnapshotSha256 ?? config.catalogSnapshotSha256,
    maximumCandidatesPerProduct: config.maximumCandidatesPerProduct,
    localReadOnly: true as const,
    targetInteraction: false as const,
    executionAuthority: "none" as const,
  });
  return Object.freeze({
    catalog: Object.freeze({
      ...unsigned,
      receiptSha256: digestCanonicalJson(unsigned, {
        maxBytes: 64 * 1_024,
        maxDepth: 12,
      }).sha256,
    }),
    ...(overrides.nvd ? { nvd: overrides.nvd } : {}),
  });
}

function nvdCompositionReceipt(
  connectionId = "public-nvd",
) {
  const unsigned = Object.freeze({
    schemaVersion:
      "ti-scale.mission-scoped-nvd-enrichment-composition.v1" as const,
    connectionId,
    toolName: "get_cve_details" as const,
    configurationSha256: "a".repeat(64),
    capabilityManifestSha256: "b".repeat(64),
    actorIdentitySha256: "c".repeat(64),
    missionScoped: true as const,
    exactCandidateOnly: true as const,
    targetInteraction: false as const,
    executionAuthority: "none" as const,
    observedAt: NOW.toISOString(),
    expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
  });
  return Object.freeze({
    ...unsigned,
    receiptSha256: createHash("sha256")
      .update(JSON.stringify(unsigned), "utf8")
      .digest("hex"),
  });
}

async function exploitCompositionFixture() {
  const root = await mkdtemp(join(tmpdir(), "ti-scale-exploit-composition-"));
  const vaultPath = join(root, "vault");
  await mkdir(vaultPath, { recursive: true });
  const database = createDatabaseConnection({
    filename: join(root, "runtime.sqlite"),
  });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, last_sync_at, created_at, updated_at
    ) VALUES ('vault-exploit-composition', ?, 'Exploit composition Vault',
      'connected', '{}', ?, ?, ?, ?)
  `).run(
    vaultPath,
    NOW.toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id,
      reason, details_json, record_hash, occurred_at
    ) VALUES ('audit-vault-exploit-composition', 'system', 'test',
      'vault.health.verified', 'vault_connection',
      'vault-exploit-composition', 'Local round trip passed', ?, ?, ?)
  `).run(
    JSON.stringify({
      connectionId: "vault-exploit-composition",
      connectionUpdatedAt: NOW.toISOString(),
      pathFingerprint: createHash("sha256")
        .update(`vault-path:${vaultPath}`, "utf8")
        .digest("hex"),
      checks: { write: true, read: true, rename: true, delete: true },
    }),
    "f".repeat(64),
    NOW.toISOString(),
  );
  const brainContext = new BrainContextService({
    database,
    secondBrain: new SecondBrainService(
      new MemoryRepository(database, { clock: () => NOW }),
    ),
    resolveExistingVaultPath: (configuredPath) => {
      if (configuredPath !== vaultPath) {
        throw new Error("Unexpected Vault path");
      }
      return vaultPath;
    },
  });
  const scriptSourceStore = new FileScriptSourceStore(
    join(root, "script-source"),
  );
  const candidateMaterializer =
    new AutonomousReusableExploitCandidateMaterializer({
      database,
      scriptSourceStore,
      brain: brainContext,
      validator: {
        async validate() {
          throw new Error("Composition tests never validate a candidate");
        },
      },
      vaultSync: {
        async synchronize() {
          throw new Error("Composition tests never synchronize candidate nodes");
        },
      },
      now: () => NOW,
    });
  const outcomeObserver =
    new CandidateSpecificIndependentExploitOutcomeVerifier({
      database,
      now: () => NOW,
    });
  return {
    root,
    database,
    brainContext,
    scriptSourceStore,
    candidateMaterializer,
    outcomeObserver,
    async dispose() {
      database.close();
      await rm(root, { recursive: true, force: true });
    },
  };
}

function exploitSandboxAttestation(): ExactTargetSandboxAttestation {
  const unsigned = Object.freeze({
    schemaVersion: "ti-scale.exact-target-sandbox-attestation.v1" as const,
    brokerVersion: "2026.07.23-v1",
    brokerExecutableSha256: "3".repeat(64),
    activationManifestSha256: "4".repeat(64),
    bubblewrapExecutableSha256: "5".repeat(64),
    interpreter: Object.freeze({
      bindingId: "python3-reviewed-v1" as const,
      language: "python" as const,
      executableSha256: "6".repeat(64),
    }),
    boundary: Object.freeze({
      platform: "linux" as const,
      directArgv: true as const,
      shell: false as const,
      immutableStagedSource: true as const,
      minimalFilesystem: "bubblewrap" as const,
      networkConfinement: "systemd_cgroup_ip_address_allow" as const,
      exactTargetEgress: true as const,
      targetPortConfinement: false as const,
      arbitraryEnvironment: false as const,
      credentialTransport: false as const,
      publicProvider: false as const,
      boundedOutput: true as const,
      boundedRuntime: true as const,
      cgroupCancellation: true as const,
      docker: false as const,
      kubernetes: false as const,
    }),
    probe: Object.freeze({
      cgroupV2: true as const,
      ipAddressDenyAny: true as const,
      exactAllowedAddressReached: true as const,
      unlistedAddressReachableWithoutFilter: true as const,
      unlistedAddressBlocked: true as const,
      probeReceiptSha256: "7".repeat(64),
    }),
    observedAt: NOW.toISOString(),
    expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
    grantsMissionExecution: false as const,
  });
  return Object.freeze({
    ...unsigned,
    receiptSha256: digestCanonicalJson(
      unsigned,
      { maxBytes: 512 * 1_024, maxDepth: 24 },
    ).sha256,
  });
}

describe("Autonomous Safe Recon production manifest join", () => {
  test("joins CVE applicability and bounded Nuclei to the live Guided tool baseline", () => {
    const manifest = productionShapedManifest();
    const receipts = manifest.list().map(({ toolId }) => activationReceipt(manifest, toolId));
    const baseline = manifest.toRuntimeSourceManifests(receipts, NOW);
    const runtimeConfiguration = configuration();

    const unbound = composeMultiToolManifests({
      baseline,
      manifest,
      activationReceipts: receipts,
      configuration: runtimeConfiguration as AutonomousDnsRuntimeConfiguration & {
        readonly ipRecon: NonNullable<AutonomousDnsRuntimeConfiguration["ipRecon"]>;
      },
      providerAttestation: providerAttestation(),
    });
    const unboundCveTool = unbound.tools.find(
      ({ id }) => id === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
    );
    expect(unboundCveTool?.available).toBeFalse();
    expect(unboundCveTool?.runtimeAdapterAttestation).toBeUndefined();

    const composed = composeMultiToolManifests({
      baseline,
      manifest,
      activationReceipts: receipts,
      configuration: runtimeConfiguration as AutonomousDnsRuntimeConfiguration & {
        readonly ipRecon: NonNullable<AutonomousDnsRuntimeConfiguration["ipRecon"]>;
      },
      providerAttestation: providerAttestation(),
      cveRuntimeComposition: cveRuntimeComposition(),
      now: NOW,
    });
    const projection = buildRuntimeCapabilityProjection(composed, NOW);

    const cveTool = composed.tools.find(
      ({ id }) => id === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
    );
    expect(cveTool?.constituentToolIds).toBeUndefined();
    expect(cveTool?.available).toBeTrue();
    expect(cveTool?.runtimeAdapterAttestation).toMatchObject({
      schemaVersion: "ti-scale.runtime-adapter-attestation.v1",
      source: "autonomous_runtime_composition",
      observedAt: NOW.toISOString(),
      expiresAt: new Date(NOW.getTime() + 59_000).toISOString(),
    });
    expect(cveTool?.runtimeAdapterAttestation?.bindingSha256)
      .toMatch(/^[a-f0-9]{64}$/u);
    const broadenedJourneyBaseline = {
      ...baseline,
      tools: [
        ...baseline.tools,
        {
          ...cveTool!,
          executionJourneys: ["autonomous", "guided"] as const,
        },
      ],
    };
    expect(() => composeMultiToolManifests({
      baseline: broadenedJourneyBaseline,
      manifest,
      activationReceipts: receipts,
      configuration: runtimeConfiguration as AutonomousDnsRuntimeConfiguration & {
        readonly ipRecon: NonNullable<AutonomousDnsRuntimeConfiguration["ipRecon"]>;
      },
      providerAttestation: providerAttestation(),
      cveRuntimeComposition: cveRuntimeComposition(),
      now: NOW,
    })).toThrow(
      `tool:${AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE}.runtimeAdapterAttestation:journey`,
    );
    const futureCveManifest = {
      ...composed,
      tools: composed.tools.map((tool) =>
        tool.id === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE
          ? {
              ...tool,
              runtimeAdapterAttestation: createRuntimeAdapterAttestation({
                toolId: tool.id,
                executionJourneys:
                  tool.runtimeAdapterAttestation!.executionJourneys,
                binding: tool.runtimeAdapterAttestation!.binding,
                observedAt: new Date(NOW.getTime() + 1_000).toISOString(),
                expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
              }),
            }
          : tool),
    };
    const futureCveProjection = buildRuntimeCapabilityProjection(futureCveManifest, NOW);
    expect(futureCveProjection.actionClasses[
      AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS
    ]).toMatchObject({
      availability: "unavailable",
      enforcementReady: false,
    });
    expect(futureCveProjection.actionClasses[
      AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS
    ].readinessReasons.join(" ")).toContain(
      "future-dated runtime-composition receipt",
    );
    const expiredCveProjection = buildRuntimeCapabilityProjection({
      ...composed,
      tools: composed.tools.map((tool) =>
        tool.id === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE
          ? {
              ...tool,
              runtimeAdapterAttestation: createRuntimeAdapterAttestation({
                toolId: tool.id,
                executionJourneys:
                  tool.runtimeAdapterAttestation!.executionJourneys,
                binding: tool.runtimeAdapterAttestation!.binding,
                observedAt: new Date(NOW.getTime() - 60_000).toISOString(),
                expiresAt: new Date(NOW.getTime() - 1).toISOString(),
              }),
            }
          : tool),
    }, NOW);
    expect(expiredCveProjection.actionClasses[
      AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS
    ]).toMatchObject({
      availability: "unavailable",
      enforcementReady: false,
    });
    expect(expiredCveProjection.actionClasses[
      AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS
    ].readinessReasons.join(" ")).toContain(
      "expired runtime-composition receipt",
    );
    expect(projection.actionClasses[AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS])
      .toMatchObject({
        availability: "supported",
        enforcementReady: true,
      });
    expect(projection.actionClasses[AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS])
      .toMatchObject({
        availability: "supported",
        enforcementReady: true,
      });
    expect(
      projection.actionClasses[AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS]
        .availableToolIds,
    ).toContain(AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE);
    expect(composed.tools.find(
      ({ id }) => id === AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
    )?.constituentToolIds).toEqual([AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID]);
    expect(composed.tools.find(
      ({ id }) => id === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
    )?.evidenceTypeIds).toEqual([AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE]);
    expect(composed.tools.find(
      ({ id }) => id === AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
    )?.evidenceTypeIds).toEqual([AUTONOMOUS_VULNERABILITY_ASSESSMENT_EVIDENCE_TYPE]);
    expect(composed.tools.find(
      ({ id }) => id === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    )?.available).toBeTrue();
    expect(composed.tools.find(
      ({ id }) => id === AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    )?.available).toBeTrue();
    expect(
      projection.actionClasses[AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS].enforcementReady,
    ).toBeTrue();
    expect(requiredAutonomousSafeReconActionClassIds(runtimeConfiguration))
      .toContain(AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS);
    expect(composed.tools.some(
      ({ id }) => id === AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
    )).toBeFalse();
  });

  test("rejects catalog and NVD composition receipts whose mounted identity differs from the reviewed configuration", () => {
    const manifest = productionShapedManifest();
    const receipts = manifest.list().map(
      ({ toolId }) => activationReceipt(manifest, toolId),
    );
    const baseline = manifest.toRuntimeSourceManifests(receipts, NOW);
    const runtimeConfiguration = configuration();
    const wrongCatalog = composeMultiToolManifests({
      baseline,
      manifest,
      activationReceipts: receipts,
      configuration: runtimeConfiguration as AutonomousDnsRuntimeConfiguration & {
        readonly ipRecon: NonNullable<AutonomousDnsRuntimeConfiguration["ipRecon"]>;
      },
      providerAttestation: providerAttestation(),
      cveRuntimeComposition: cveRuntimeComposition({
        catalogId: "catalog:swapped-authority",
      }),
      now: NOW,
    });
    const wrongCatalogTool = wrongCatalog.tools.find(
      ({ id }) => id === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
    );
    expect(wrongCatalogTool).toMatchObject({ available: false });
    expect(wrongCatalogTool?.runtimeAdapterAttestation).toBeUndefined();

    const topCandidateConfiguration = Object.freeze({
      ...runtimeConfiguration,
      cveApplicability: Object.freeze({
        ...runtimeConfiguration.cveApplicability!,
        nvdEnrichment: "top_candidate" as const,
      }),
    }) as AutonomousDnsRuntimeConfiguration & {
      readonly ipRecon: NonNullable<AutonomousDnsRuntimeConfiguration["ipRecon"]>;
      readonly cveApplicability: NonNullable<
        AutonomousDnsRuntimeConfiguration["cveApplicability"]
      >;
    };
    const wrongNvd = composeMultiToolManifests({
      baseline,
      manifest,
      activationReceipts: receipts,
      configuration: topCandidateConfiguration,
      providerAttestation: providerAttestation(),
      cveRuntimeComposition: cveRuntimeComposition({
        nvd: nvdCompositionReceipt("public-nvd-swapped"),
      }),
      now: NOW,
    });
    const wrongNvdTool = wrongNvd.tools.find(
      ({ id }) => id === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
    );
    expect(wrongNvdTool).toMatchObject({ available: false });
    expect(wrongNvdTool?.runtimeAdapterAttestation).toBeUndefined();
  });

  test("issues independently verifiable bounded receipts for the exact mounted exploit components", async () => {
    const fixture = await exploitCompositionFixture();
    try {
      const materializerReceipt =
        fixture.candidateMaterializer.inspectComposition(NOW);
      const observerReceipt = fixture.outcomeObserver.inspectComposition(NOW);
      const sourceStoreReceipt =
        fixture.scriptSourceStore.inspectComposition(NOW);
      const brainReceipt = fixture.brainContext.inspectComposition(NOW);

      expect(observerReceipt).toBeDefined();
      expect(brainReceipt).toBeDefined();
      expect(
        autonomousReusableExploitMaterializerCompositionReceiptValid(
          materializerReceipt,
          NOW,
        ),
      ).toBeTrue();
      expect(
        autonomousExploitOutcomeObserverCompositionReceiptValid(
          observerReceipt!,
          NOW,
        ),
      ).toBeTrue();
      expect(materializerReceipt).toMatchObject({
        databaseIdentitySha256: observerReceipt!.databaseIdentitySha256,
        databaseMigrationVersion: observerReceipt!.databaseMigrationVersion,
        scriptSourceStoreReceiptSha256: sourceStoreReceipt.receiptSha256,
        brainContextReceiptSha256: brainReceipt!.receiptSha256,
        observedAt: NOW.toISOString(),
        expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
      });
      expect(observerReceipt).toMatchObject({
        observerServiceId:
          "ti-scale.candidate-specific-independent-exploit-outcome-observer.v1",
        ready: true,
        specRegistrySha256:
          exploitOutcomeObserverSpecRegistrySha256(fixture.database),
        observedAt: NOW.toISOString(),
        expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
      });
      expect(materializerReceipt.receiptSha256)
        .not.toBe(observerReceipt!.receiptSha256);

      const materializerUnsigned = (({
        receiptSha256: _receiptSha256,
        ...unsigned
      }) => unsigned)(materializerReceipt);
      const observerUnsigned = (({
        receiptSha256: _receiptSha256,
        ...unsigned
      }) => unsigned)(observerReceipt!);
      for (const times of [
        {
          observedAt: new Date(NOW.getTime() + 1).toISOString(),
          expiresAt: new Date(NOW.getTime() + 60_001).toISOString(),
        },
        {
          observedAt: new Date(NOW.getTime() - 120_000).toISOString(),
          expiresAt: new Date(NOW.getTime() - 60_000).toISOString(),
        },
        {
          observedAt: NOW.toISOString(),
          expiresAt: new Date(NOW.getTime() + 5 * 60_000 + 1).toISOString(),
        },
      ]) {
        const materializerCandidate = Object.freeze({
          ...materializerUnsigned,
          ...times,
        });
        const materializerResigned = Object.freeze({
          ...materializerCandidate,
          receiptSha256: digestCanonicalJson(materializerCandidate, {
            maxBytes: 64 * 1_024,
            maxDepth: 12,
          }).sha256,
        });
        expect(
          autonomousReusableExploitMaterializerCompositionReceiptValid(
            materializerResigned,
            NOW,
          ),
        ).toBeFalse();

        const observerCandidate = Object.freeze({
          ...observerUnsigned,
          ...times,
        });
        const observerResigned = Object.freeze({
          ...observerCandidate,
          receiptSha256: digestCanonicalJson(observerCandidate, {
            maxBytes: 128 * 1_024,
            maxDepth: 16,
          }).sha256,
        });
        expect(
          autonomousExploitOutcomeObserverCompositionReceiptValid(
            observerResigned,
            NOW,
          ),
        ).toBeFalse();
      }
    } finally {
      await fixture.dispose();
    }
  });

  test("keeps exploit validation unavailable until materializer, observer, and sandbox are all ready", async () => {
    const fixture = await exploitCompositionFixture();
    try {
      const manifest = productionShapedManifest();
      const receipts = manifest.list().map(
        ({ toolId }) => activationReceipt(manifest, toolId),
      );
      const baseline = manifest.toRuntimeSourceManifests(receipts, NOW);
      const runtimeConfiguration = Object.freeze({
        ...configuration(),
        exploitValidation: Object.freeze({
          schemaVersion:
            "ti-scale.autonomous-exploit-validation-runtime-configuration.v1" as const,
          configurationVersion: "exact-target-test-v1",
          bindingId: "binding:autonomous-exact-target-test-v1",
          agentId: AGENT_ID,
          providerId: PROVIDER_ID,
          modelId: MODEL_ID,
          modelConfigurationHash: MODEL_CONFIGURATION_HASH,
          logicalWorkspace: WORKSPACE,
          successCriterion:
            "One approved evidence-matched ScriptArtifact produced an attributable reviewable result",
        }),
      }) as AutonomousDnsRuntimeConfiguration & {
        readonly ipRecon: NonNullable<AutonomousDnsRuntimeConfiguration["ipRecon"]>;
        readonly exploitValidation: NonNullable<
          AutonomousDnsRuntimeConfiguration["exploitValidation"]
        >;
      };
      const input = {
        baseline,
        manifest,
        activationReceipts: receipts,
        configuration: runtimeConfiguration,
        providerAttestation: providerAttestation(),
        cveRuntimeComposition: cveRuntimeComposition(),
        database: fixture.database,
        scriptSourceStore: fixture.scriptSourceStore,
        brainContext: fixture.brainContext,
        now: NOW,
      };
      const unavailable = composeMultiToolManifests({
        ...input,
        exploitSandboxAttestation: exploitSandboxAttestation(),
      });
      const unavailableProjection = buildRuntimeCapabilityProjection(unavailable, NOW);
      expect(unavailable.tools.find(
        ({ id }) => id === AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
      )).toMatchObject({
        available: false,
        dependencies: [
          { id: "candidate-specific-materializer", ready: false },
          { id: "independent-target-impact-observer", ready: false },
          { id: "exact-target-sandbox", ready: true },
          { id: "immutable-script-source-store", ready: true },
          { id: "active-second-brain-context", ready: true },
        ],
      });
      expect(unavailableProjection.actionClasses[AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS])
        .toMatchObject({
          availability: "unavailable",
          enforcementReady: false,
        });
      expect(
        unavailableProjection.actionClasses[AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS]
          .readinessReasons.join(" "),
      ).toContain("candidate-specific-materializer");

      const materializerReceipt =
        fixture.candidateMaterializer.inspectComposition(NOW);
      const observerReceipt = fixture.outcomeObserver.inspectComposition(NOW)!;
      const scriptSourceStoreReceipt =
        fixture.scriptSourceStore.inspectComposition(NOW);
      const brainContextReceipt =
        fixture.brainContext.inspectComposition(NOW)!;
      const sandboxAttestation = exploitSandboxAttestation();
      const composed = composeMultiToolManifests({
        ...input,
        exploitCandidateMaterializer: fixture.candidateMaterializer,
        exploitOutcomeObserver: fixture.outcomeObserver,
        exploitSandboxAttestation: sandboxAttestation,
      });
      const projection = buildRuntimeCapabilityProjection(composed, NOW);
      const tool = composed.tools.find(
        ({ id }) => id === AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
      );
      expect(tool).toMatchObject({
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: false,
        executionJourneys: ["autonomous"],
        actionClassIds: [AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS],
        evidenceTypeIds: ["exploit_validation_result", "finding_reproduction"],
        runtimeAdapterAttestation: {
          schemaVersion: "ti-scale.runtime-adapter-attestation.v1",
          source: "autonomous_runtime_composition",
          observedAt: NOW.toISOString(),
          expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
        },
      });
      expect(tool?.runtimeAdapterAttestation?.bindingSha256)
        .toMatch(/^[a-f0-9]{64}$/u);
      expect(tool?.dependencies).toHaveLength(5);
      expect(tool?.dependencies?.every((dependency) =>
        dependency.runtimeAdapterAttestation?.bindingSha256
        && dependency.runtimeAdapterAttestation.bindingSha256
          !== tool.runtimeAdapterAttestation?.bindingSha256)).toBeTrue();
      expect(new Set(tool?.dependencies?.map((dependency) =>
        dependency.runtimeAdapterAttestation?.bindingSha256)).size).toBe(5);
      expect(tool?.runtimeAdapterAttestation?.binding.componentReceiptSha256s)
        .toEqual([
          sandboxAttestation.receiptSha256,
          materializerReceipt.receiptSha256,
          observerReceipt.receiptSha256,
          scriptSourceStoreReceipt.receiptSha256,
          brainContextReceipt.receiptSha256,
        ].sort());
      const dependencyReceiptById = new Map([
        ["candidate-specific-materializer", materializerReceipt.receiptSha256],
        ["independent-target-impact-observer", observerReceipt.receiptSha256],
        ["exact-target-sandbox", sandboxAttestation.receiptSha256],
        ["immutable-script-source-store", scriptSourceStoreReceipt.receiptSha256],
        ["active-second-brain-context", brainContextReceipt.receiptSha256],
      ]);
      for (const dependency of tool?.dependencies ?? []) {
        const expectedComponentReceiptSha256 =
          dependencyReceiptById.get(dependency.id);
        if (!expectedComponentReceiptSha256) {
          throw new Error(`Unexpected exploit dependency: ${dependency.id}`);
        }
        expect(dependency.runtimeAdapterAttestation?.parentBindingSha256)
          .toBe(tool?.runtimeAdapterAttestation?.bindingSha256);
        expect(
          dependency.runtimeAdapterAttestation?.binding
            .componentReceiptSha256s,
        ).toEqual([expectedComponentReceiptSha256]);
      }
      expect(projection.actionClasses[AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS])
        .toMatchObject({
          availability: "supported",
          enforcementReady: true,
        });
      expect(composed.agents.find(({ id }) => id === AGENT_ID)?.toolIds)
        .toContain(AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE);
      expect(composed.providers.find(({ id }) => id === PROVIDER_ID)
        ?.models[0]?.compatibleActionClassIds)
        .toContain(AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS);

      // A broker can be installed and attested for production-path proof
      // without making any post-exploit action mission-executable.
      expect(AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS.every(
        (toolId) => composed.tools.some(({ id, available, dependencies }) =>
          id === toolId
          && available === false
          && dependencies?.some((dependency) =>
            dependency.id === "reviewed-candidate-linux-transport"
            && dependency.ready === false)),
      )).toBeTrue();
      for (const actionClassId of AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES) {
        expect(projection.actionClasses[actionClassId]).toMatchObject({
          enforcementReady: false,
        });
        expect(
          projection.actionClasses[actionClassId].readinessReasons.join(" "),
        ).toContain("reviewed-candidate-linux-transport");
      }
      const completeEngagement = new MissionIntakeService({
        readRuntimeManifests: () => composed,
        clock: () => NOW,
      }).resolve({
        journey: "autonomous",
        authorizationAcknowledged: true,
        targets: [{ value: "127.0.0.1" }],
        templateId: "htb_web_full_path",
        environmentClassification: "htb",
      });
      expect(completeEngagement.policyMatrix.autonomousLaunchReady).toBeFalse();
      expect(
        completeEngagement.policyMatrix.launchBlockingReasons.join(" "),
      ).toContain("reviewed-candidate-linux-transport");
      expect(AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES.every(
        (actionClassId) =>
          !requiredAutonomousSafeReconActionClassIds(runtimeConfiguration)
            .includes(actionClassId),
      )).toBeTrue();

      const reviewedRealCandidate = composeMultiToolManifests({
        ...input,
        exploitCandidateMaterializer: fixture.candidateMaterializer,
        exploitOutcomeObserver: fixture.outcomeObserver,
        exploitSandboxAttestation: exploitSandboxAttestation(),
        candidateLinuxTransportReady: true,
      });
      expect(AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS.every(
        (toolId) => reviewedRealCandidate.tools.some(
          ({ id, available }) => id === toolId && available,
        ),
      )).toBeTrue();
      expect(AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES.every(
        (actionClassId) =>
          requiredAutonomousSafeReconActionClassIds(
            runtimeConfiguration,
            true,
          ).includes(actionClassId),
      )).toBeTrue();
    } finally {
      await fixture.dispose();
    }
  });
});

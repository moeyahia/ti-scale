import { createHash } from "node:crypto";
import {
  constants,
  existsSync,
  lstatSync,
  realpathSync,
} from "node:fs";
import {
  mkdir,
  open,
  readFile,
  rm,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import {
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID,
  AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION,
  AUTONOMOUS_FULL_TCP_BASELINE_BINDING_ID,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_TOOL_ID,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_BINDING_ID,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_POLICY_SCHEMA_VERSION,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID,
  AUTONOMOUS_VULNERABILITY_MAX_ORIGINS,
  AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_ID,
  AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_SHA256,
  createAutonomousFullTcpBaselineManifest,
  createAutonomousGeneralSafeReconPlanningPolicy,
  createAutonomousVulnerabilityAssessmentToolRecord,
} from "../../server/autonomous-runtime";
import {
  cveCandidateCatalogSnapshotSha256,
  parsePinnedLocalCveCandidateCatalogDocument,
  type PinnedLocalCveCandidateCatalogDocument,
} from "../../server/cve-intelligence";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
  AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
  AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_SUCCESS_CRITERION,
} from "../../server/domain";
import {
  LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
  LocalToolCapabilityManifest,
  loadTrustedLocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
  type LocalToolCapabilityManifestDocument,
} from "../../server/local-tools";
import { digestCanonicalJson } from "../../server/mcp";
import {
  AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
  loadTrustedAutonomousDnsRuntimeConfiguration,
  parseAutonomousDnsRuntimeConfiguration,
  type AutonomousDnsRuntimeConfiguration,
} from "../../server/app/AutonomousDnsActivationCoordinator";
import {
  loadTrustedJson,
  type TrustedJsonFileReference,
} from "../../server/trusted-runtime-config";
import { composeReviewedWebAssessmentLocalManifest } from "../../server/web-assessment-tools";

export const FULL_TCP_ACTIVATION_DOCUMENTS_SCHEMA_VERSION =
  "ti-scale.full-tcp-activation-documents.v1" as const;
export const FULL_TCP_ACTIVATION_MANIFEST_VERSION =
  "kali-local-general-safe-recon-2026.07.22-v3" as const;
export const FULL_TCP_ACTIVATION_RUNTIME_VERSION =
  "autonomous-general-safe-recon-local-2026.07.22-v3" as const;
export const FULL_TCP_ACTIVATION_MANIFEST_NAME =
  "local-tool-capabilities.v1.json" as const;
export const FULL_TCP_ACTIVATION_RUNTIME_NAME =
  "autonomous-dns-local-runtime.v1.json" as const;
export const FULL_TCP_ACTIVATION_HASH_FRAGMENT_NAME =
  "activation-sha256.values.conf" as const;
export const AUTONOMOUS_CVE_CANDIDATE_CATALOG_NAME =
  "autonomous-cve-candidate-catalog.v1.json" as const;
export const AUTONOMOUS_HTTP_METADATA_BINDING_ID =
  "binding:autonomous-http-metadata-v1" as const;
export const AUTONOMOUS_WHATWEB_FINGERPRINT_BINDING_ID =
  "binding:autonomous-whatweb-fingerprint-v1" as const;
export const AUTONOMOUS_ENDPOINT_DISCOVERY_BINDING_ID =
  "binding:autonomous-endpoint-discovery-v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const VERSION = /^[A-Za-z0-9._-]{1,80}$/u;
const UNSAFE_ENVIRONMENT_PATH = /[\s#'"\\\u0000-\u001F\u007F]/u;

type ToolDocument = LocalToolCapabilityManifestDocument["tools"][number];

export interface FullTcpSafeReconActivationInput {
  readonly sourceManifest: TrustedJsonFileReference;
  readonly sourceRuntime: TrustedJsonFileReference;
  /** Optional reviewed local catalogue; enables the local CVE phase with NVD disabled. */
  readonly sourceCveCandidateCatalog?: TrustedJsonFileReference;
  readonly maximumCveCandidatesPerProduct?: number;
  /** Must be an explicit absolute, not-yet-existing directory outside /etc. */
  readonly outputDirectory: string;
  readonly manifestVersion?: string;
  readonly configurationVersion?: string;
}

export interface FullTcpSafeReconActivationResult {
  readonly schemaVersion: typeof FULL_TCP_ACTIVATION_DOCUMENTS_SCHEMA_VERSION;
  readonly outputDirectory: string;
  readonly source: Readonly<{
    readonly manifestSha256: string;
    readonly runtimeSha256: string;
    readonly cveCandidateCatalogSha256?: string;
  }>;
  readonly generated: Readonly<{
    readonly manifest: Readonly<{ readonly path: string; readonly sha256: string }>;
    readonly runtime: Readonly<{ readonly path: string; readonly sha256: string }>;
    readonly activationHashFragment: Readonly<{ readonly path: string; readonly sha256: string }>;
    readonly cveCandidateCatalog?: Readonly<{ readonly path: string; readonly sha256: string }>;
  }>;
  readonly activationEnvironmentValues: Readonly<{
    readonly TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256: string;
    readonly TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_SHA256: string;
    readonly TI_SCALE_AUTONOMOUS_CVE_CANDIDATE_CATALOG_SHA256?: string;
  }>;
  readonly phaseToolIds: readonly [
    typeof AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    typeof AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  ];
  readonly webToolIds: readonly [
    typeof AUTONOMOUS_HTTP_METADATA_TOOL_ID,
    typeof AUTONOMOUS_WHATWEB_TOOL_ID,
    typeof AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  ];
  readonly vulnerabilityToolId: typeof AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID;
  readonly plannerBindingIds: readonly string[];
  readonly adapterId: typeof AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID;
  readonly successCriterion: typeof AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION;
}

function sha256(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function documentBytes(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function outputDirectory(value: string): string {
  if (!value || !isAbsolute(value) || UNSAFE_ENVIRONMENT_PATH.test(value)) {
    throw new Error("Full-TCP activation outputDirectory must be one safe absolute path");
  }
  const normalized = resolve(value);
  if (normalized !== value || normalized === resolve(sep)) {
    throw new Error("Full-TCP activation outputDirectory must be normalized and narrower than the filesystem root");
  }
  const relativeToEtc = relative("/etc", normalized);
  if (relativeToEtc === "" || (!relativeToEtc.startsWith(`..${sep}`) && relativeToEtc !== "..")) {
    throw new Error("Full-TCP activation document generation never writes below /etc");
  }
  if (existsSync(normalized)) {
    throw new Error("Full-TCP activation outputDirectory must not already exist");
  }
  const parent = dirname(normalized);
  const metadata = lstatSync(parent);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(parent) !== parent) {
    throw new Error("Full-TCP activation outputDirectory parent must be one existing non-symlink directory");
  }
  return normalized;
}

function version(value: string | undefined, fallback: string, label: string): string {
  const selected = value ?? fallback;
  if (!VERSION.test(selected)) throw new Error(`${label} must be a stable document version`);
  return selected;
}

function withoutBindingSha256(tool: ReturnType<LocalToolCapabilityManifest["list"]>[number]): ToolDocument {
  const { bindingSha256: _bindingSha256, ...document } = tool;
  return document;
}

function exactToolHash(tool: ToolDocument): string {
  return digestCanonicalJson(tool, { maxBytes: 128 * 1_024, maxDepth: 16 }).sha256;
}

function appendExactFullTcpTools(
  source: LocalToolCapabilityManifest,
  manifestVersion: string,
): LocalToolCapabilityManifestDocument {
  const phaseManifest = createAutonomousFullTcpBaselineManifest();
  const phaseTools = phaseManifest.list().map(withoutBindingSha256);
  const phaseIds = new Set(phaseTools.map(({ toolId }) => toolId));
  const collision = source.list().find(({ toolId }) => phaseIds.has(toolId));
  if (collision) {
    throw new Error(`Source manifest already contains Full-TCP phase tool ${collision.toolId}`);
  }
  const sourceTools = source.list().map(withoutBindingSha256);
  const fullTcpDocument = parseLocalToolCapabilityManifestDocument({
    schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    manifestVersion: `${manifestVersion}-base`,
    specialist: source.specialist,
    tools: [...sourceTools, ...phaseTools],
  });
  if (fullTcpDocument.tools.length !== sourceTools.length + 2) {
    throw new Error("Full-TCP activation manifest did not add exactly two phase tools");
  }
  for (const expected of phaseTools) {
    const actual = fullTcpDocument.tools.find(({ toolId }) => toolId === expected.toolId);
    if (!actual || exactToolHash(actual) !== exactToolHash(expected)) {
      throw new Error(`Generated Full-TCP phase tool drifted from reviewed source ${expected.toolId}`);
    }
  }
  const parsed = parseLocalToolCapabilityManifestDocument({
    schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    manifestVersion,
    specialist: fullTcpDocument.specialist,
    tools: fullTcpDocument.tools,
  });
  if (parsed.tools.length !== sourceTools.length + 2) {
    throw new Error("Safe Recon activation manifest did not add exactly the two Full-TCP tools");
  }
  if (parsed.tools.some(({ toolId }) => toolId === AUTONOMOUS_WHATWEB_TOOL_ID)) {
    throw new Error(
      "Safe Recon activation manifest must not duplicate WhatWeb composed by the production loader",
    );
  }
  return parsed;
}

function appendExactVulnerabilityTool(
  source: LocalToolCapabilityManifestDocument,
  manifestVersion: string,
): LocalToolCapabilityManifestDocument {
  if (source.tools.some(({ toolId }) =>
    toolId === AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID)) {
    throw new Error("Source manifest already contains the bounded Nuclei tool");
  }
  const tool = createAutonomousVulnerabilityAssessmentToolRecord();
  const parsed = parseLocalToolCapabilityManifestDocument({
    schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    manifestVersion,
    specialist: source.specialist,
    tools: [...source.tools, tool],
  });
  const actual = parsed.tools.find(({ toolId }) =>
    toolId === AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID);
  if (!actual || exactToolHash(actual) !== exactToolHash(tool)) {
    throw new Error("Generated bounded Nuclei tool drifted from its reviewed binding");
  }
  return parsed;
}

function upgradedRuntime(
  source: AutonomousDnsRuntimeConfiguration,
  configurationVersion: string,
  cveCatalog?: PinnedLocalCveCandidateCatalogDocument,
  maximumCveCandidatesPerProduct = 25,
): AutonomousDnsRuntimeConfiguration {
  if (!source.ipRecon) {
    throw new Error("Full-TCP activation requires the existing bounded ipRecon configuration");
  }
  return parseAutonomousDnsRuntimeConfiguration({
    ...source,
    schemaVersion: AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
    configurationVersion,
    dns: source.dns,
    ipRecon: source.ipRecon,
    fullTcpBaseline: {
      policyId: source.dns.policyId,
      bindingId: AUTONOMOUS_FULL_TCP_BASELINE_BINDING_ID,
      agentId: source.dns.agentId,
      providerId: source.dns.providerId,
      modelId: source.dns.modelId,
      modelConfigurationHash: source.dns.modelConfigurationHash,
      logicalWorkspace: source.ipRecon.logicalWorkspace,
      successCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
    },
    webSurface: {
      policyId: source.dns.policyId,
      httpMetadataBindingId: AUTONOMOUS_HTTP_METADATA_BINDING_ID,
      whatwebBindingId: AUTONOMOUS_WHATWEB_FINGERPRINT_BINDING_ID,
      endpointDiscoveryBindingId: AUTONOMOUS_ENDPOINT_DISCOVERY_BINDING_ID,
      agentId: source.dns.agentId,
      providerId: source.dns.providerId,
      modelId: source.dns.modelId,
      modelConfigurationHash: source.dns.modelConfigurationHash,
      logicalWorkspace: source.ipRecon.logicalWorkspace,
      maximumOrigins: AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
      httpMetadataSuccessCriterion: AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
      whatwebSuccessCriterion: AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
      endpointDiscoverySuccessCriterion: AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
    },
    ...(cveCatalog ? {
      cveApplicability: {
        policyId: source.dns.policyId,
        bindingId: AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID,
        agentId: source.dns.agentId,
        providerId: source.dns.providerId,
        modelId: source.dns.modelId,
        modelConfigurationHash: source.dns.modelConfigurationHash,
        catalogId: cveCatalog.catalogId,
        catalogSnapshotSha256: cveCandidateCatalogSnapshotSha256(cveCatalog),
        maximumCandidatesPerProduct: maximumCveCandidatesPerProduct,
        nvdEnrichment: "disabled",
        successCriterion: AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION,
      },
    } : {}),
    vulnerabilityAssessment: {
      schemaVersion: AUTONOMOUS_VULNERABILITY_ASSESSMENT_POLICY_SCHEMA_VERSION,
      policyId: source.dns.policyId,
      bindingId: AUTONOMOUS_VULNERABILITY_ASSESSMENT_BINDING_ID,
      agentId: source.dns.agentId,
      providerId: source.dns.providerId,
      modelId: source.dns.modelId,
      modelConfigurationHash: source.dns.modelConfigurationHash,
      logicalWorkspace: source.ipRecon.logicalWorkspace,
      maximumOrigins: AUTONOMOUS_VULNERABILITY_MAX_ORIGINS,
      templatePackId: AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_ID,
      templatePackSha256: AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_SHA256,
      successCriterion: AUTONOMOUS_VULNERABILITY_ASSESSMENT_SUCCESS_CRITERION,
    },
    localProcess: { adapterId: AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID },
    specialist: source.specialist,
    provider: source.provider,
    ...(source.mcp ? { mcp: source.mcp } : {}),
  });
}

async function writeExclusive(path: string, bytes: string): Promise<void> {
  const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  try {
    await handle.writeFile(bytes, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function validateGeneratedPair(
  manifestDocument: LocalToolCapabilityManifestDocument,
  runtimeDocument: AutonomousDnsRuntimeConfiguration,
): void {
  const baseManifest = new LocalToolCapabilityManifest(manifestDocument);
  // Production composes the independently reviewed web-assessment manifest
  // when TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED=true. Validate that exact
  // path here without persisting duplicate WhatWeb/FFUF tool IDs.
  const manifest = composeReviewedWebAssessmentLocalManifest(baseManifest);
  if (!runtimeDocument.ipRecon || !runtimeDocument.fullTcpBaseline
    || !runtimeDocument.webSurface) {
    throw new Error("Generated runtime did not retain IP recon and add Full-TCP plus web-surface configuration");
  }
  const policy = createAutonomousGeneralSafeReconPlanningPolicy(
    runtimeDocument.dns,
    runtimeDocument.ipRecon,
    runtimeDocument.fullTcpBaseline,
    manifest,
    runtimeDocument.webSurface,
    runtimeDocument.cveApplicability,
    runtimeDocument.vulnerabilityAssessment,
  );
  const expectedPlannerBindings = [
    [runtimeDocument.dns.bindingId, AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID],
    [runtimeDocument.ipRecon.livenessBindingId, AUTONOMOUS_IP_LIVENESS_TOOL_ID],
    [runtimeDocument.fullTcpBaseline.bindingId, AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE],
    [runtimeDocument.webSurface.httpMetadataBindingId, AUTONOMOUS_HTTP_METADATA_ACTION_TYPE],
    [runtimeDocument.webSurface.whatwebBindingId, AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE],
    [runtimeDocument.webSurface.endpointDiscoveryBindingId, AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE],
    ...(runtimeDocument.cveApplicability ? [[
      runtimeDocument.cveApplicability.bindingId,
      AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
    ] as const] : []),
    ...(runtimeDocument.vulnerabilityAssessment ? [[
      runtimeDocument.vulnerabilityAssessment.bindingId,
      AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
    ] as const] : []),
  ] as const;
  if (policy.bindings.length !== expectedPlannerBindings.length
    || expectedPlannerBindings.some(([bindingId, toolId]) => policy.bindings.filter((binding) =>
      binding.bindingId === bindingId
      && "toolId" in binding
      && binding.toolId === toolId).length !== 1)) {
    throw new Error("Generated runtime planner authority is not the exact reviewed binding set");
  }
  const physicalToolIds = [
    AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    AUTONOMOUS_HTTP_METADATA_TOOL_ID,
    AUTONOMOUS_WHATWEB_TOOL_ID,
    AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
    AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID,
  ] as const;
  if (physicalToolIds.some((toolId) => manifest.resolve(toolId)?.activation !== "enabled")) {
    throw new Error("Generated manifest does not expose every physical tool required by the six planner bindings");
  }
}

/**
 * Builds reviewed activation documents only. It never probes tools, writes
 * service state, edits /etc, creates a backup, or mutates its trusted inputs.
 */
export async function generateFullTcpSafeReconActivationDocuments(
  input: FullTcpSafeReconActivationInput,
): Promise<FullTcpSafeReconActivationResult> {
  const target = outputDirectory(input.outputDirectory);
  const manifestVersion = version(
    input.manifestVersion,
    FULL_TCP_ACTIVATION_MANIFEST_VERSION,
    "manifestVersion",
  );
  const configurationVersion = version(
    input.configurationVersion,
    FULL_TCP_ACTIVATION_RUNTIME_VERSION,
    "configurationVersion",
  );
  if (input.maximumCveCandidatesPerProduct !== undefined
    && input.sourceCveCandidateCatalog === undefined) {
    throw new Error("maximumCveCandidatesPerProduct requires sourceCveCandidateCatalog");
  }
  const maximumCveCandidatesPerProduct = input.maximumCveCandidatesPerProduct ?? 25;
  if (!Number.isSafeInteger(maximumCveCandidatesPerProduct)
    || maximumCveCandidatesPerProduct < 1
    || maximumCveCandidatesPerProduct > 100) {
    throw new RangeError("maximumCveCandidatesPerProduct must be 1 through 100");
  }
  const sourceManifest = loadTrustedLocalToolCapabilityManifest(input.sourceManifest);
  const sourceRuntime = loadTrustedAutonomousDnsRuntimeConfiguration(input.sourceRuntime);
  const sourceCveCandidateCatalog = input.sourceCveCandidateCatalog
    ? loadTrustedJson(
        input.sourceCveCandidateCatalog,
        parsePinnedLocalCveCandidateCatalogDocument,
      )
    : undefined;
  const fullTcpManifestDocument =
    appendExactFullTcpTools(sourceManifest.value, `${manifestVersion}-tcp`);
  const manifestDocument = appendExactVulnerabilityTool(
    fullTcpManifestDocument,
    manifestVersion,
  );
  const runtimeDocument = upgradedRuntime(
    sourceRuntime.value,
    configurationVersion,
    sourceCveCandidateCatalog?.value,
    maximumCveCandidatesPerProduct,
  );
  validateGeneratedPair(manifestDocument, runtimeDocument);

  const manifestBytes = documentBytes(manifestDocument);
  const runtimeBytes = documentBytes(runtimeDocument);
  const cveCandidateCatalogBytes = sourceCveCandidateCatalog
    ? documentBytes(sourceCveCandidateCatalog.value)
    : undefined;
  const manifestSha256 = sha256(manifestBytes);
  const runtimeSha256 = sha256(runtimeBytes);
  const cveCandidateCatalogSha256 = cveCandidateCatalogBytes
    ? sha256(cveCandidateCatalogBytes)
    : undefined;
  const hashFragment = [
    `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256=${manifestSha256}`,
    `TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_SHA256=${runtimeSha256}`,
    ...(cveCandidateCatalogSha256 ? [
      `TI_SCALE_AUTONOMOUS_CVE_CANDIDATE_CATALOG_SHA256=${cveCandidateCatalogSha256}`,
    ] : []),
    "",
  ].join("\n");
  const paths = {
    manifest: join(target, FULL_TCP_ACTIVATION_MANIFEST_NAME),
    runtime: join(target, FULL_TCP_ACTIVATION_RUNTIME_NAME),
    cveCandidateCatalog: join(target, AUTONOMOUS_CVE_CANDIDATE_CATALOG_NAME),
    activationHashFragment: join(target, FULL_TCP_ACTIVATION_HASH_FRAGMENT_NAME),
  } as const;

  let created = false;
  try {
    await mkdir(target, { mode: 0o700 });
    created = true;
    await writeExclusive(paths.manifest, manifestBytes);
    await writeExclusive(paths.runtime, runtimeBytes);
    if (cveCandidateCatalogBytes) {
      await writeExclusive(paths.cveCandidateCatalog, cveCandidateCatalogBytes);
    }
    await writeExclusive(paths.activationHashFragment, hashFragment);

    const persistedManifest = parseLocalToolCapabilityManifestDocument(
      JSON.parse(await readFile(paths.manifest, "utf8")) as unknown,
    );
    const persistedRuntime = parseAutonomousDnsRuntimeConfiguration(
      JSON.parse(await readFile(paths.runtime, "utf8")) as unknown,
    );
    const persistedCveCandidateCatalog = cveCandidateCatalogBytes
      ? parsePinnedLocalCveCandidateCatalogDocument(
          JSON.parse(await readFile(paths.cveCandidateCatalog, "utf8")) as unknown,
        )
      : undefined;
    validateGeneratedPair(persistedManifest, persistedRuntime);
    if (persistedRuntime.cveApplicability && persistedCveCandidateCatalog
      && (persistedRuntime.cveApplicability.catalogId !== persistedCveCandidateCatalog.catalogId
        || persistedRuntime.cveApplicability.catalogSnapshotSha256
          !== cveCandidateCatalogSnapshotSha256(persistedCveCandidateCatalog))) {
      throw new Error("Persisted CVE catalogue does not match the generated runtime pin");
    }
    if (
      sha256(await readFile(paths.manifest)) !== manifestSha256
      || sha256(await readFile(paths.runtime)) !== runtimeSha256
      || (cveCandidateCatalogSha256
        && sha256(await readFile(paths.cveCandidateCatalog)) !== cveCandidateCatalogSha256)
      || sha256(await readFile(paths.activationHashFragment)) !== sha256(hashFragment)
    ) {
      throw new Error("Persisted Full-TCP activation documents failed byte-hash verification");
    }
  } catch (error) {
    if (created) await rm(target, { recursive: true, force: true });
    throw error;
  }

  return Object.freeze({
    schemaVersion: FULL_TCP_ACTIVATION_DOCUMENTS_SCHEMA_VERSION,
    outputDirectory: target,
    source: Object.freeze({
      manifestSha256: sourceManifest.receipt.sourceSha256,
      runtimeSha256: sourceRuntime.receipt.sourceSha256,
      ...(sourceCveCandidateCatalog ? {
        cveCandidateCatalogSha256: sourceCveCandidateCatalog.receipt.sourceSha256,
      } : {}),
    }),
    generated: Object.freeze({
      manifest: Object.freeze({ path: paths.manifest, sha256: manifestSha256 }),
      runtime: Object.freeze({ path: paths.runtime, sha256: runtimeSha256 }),
      ...(cveCandidateCatalogSha256 ? {
        cveCandidateCatalog: Object.freeze({
          path: paths.cveCandidateCatalog,
          sha256: cveCandidateCatalogSha256,
        }),
      } : {}),
      activationHashFragment: Object.freeze({
        path: paths.activationHashFragment,
        sha256: sha256(hashFragment),
      }),
    }),
    activationEnvironmentValues: Object.freeze({
      TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256: manifestSha256,
      TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_SHA256: runtimeSha256,
      ...(cveCandidateCatalogSha256 ? {
        TI_SCALE_AUTONOMOUS_CVE_CANDIDATE_CATALOG_SHA256:
          cveCandidateCatalogSha256,
      } : {}),
    }),
    phaseToolIds: Object.freeze([
      AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
      AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    ]) as FullTcpSafeReconActivationResult["phaseToolIds"],
    webToolIds: Object.freeze([
      AUTONOMOUS_HTTP_METADATA_TOOL_ID,
      AUTONOMOUS_WHATWEB_TOOL_ID,
      AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
    ]) as FullTcpSafeReconActivationResult["webToolIds"],
    vulnerabilityToolId: AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID,
    plannerBindingIds: Object.freeze([
      runtimeDocument.dns.bindingId,
      runtimeDocument.ipRecon!.livenessBindingId,
      AUTONOMOUS_FULL_TCP_BASELINE_BINDING_ID,
      AUTONOMOUS_HTTP_METADATA_BINDING_ID,
      AUTONOMOUS_WHATWEB_FINGERPRINT_BINDING_ID,
      AUTONOMOUS_ENDPOINT_DISCOVERY_BINDING_ID,
      ...(runtimeDocument.cveApplicability
        ? [AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID]
        : []),
      AUTONOMOUS_VULNERABILITY_ASSESSMENT_BINDING_ID,
    ]) as FullTcpSafeReconActivationResult["plannerBindingIds"],
    adapterId: AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID,
    successCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
  });
}

import {
  inspectCanonicalDatabaseIdentity,
  type SqliteDatabase,
} from "../db";
import {
  BrainContextService,
  brainContextServiceCompositionReceiptValid,
  type BrainContextServiceCompositionReceipt,
} from "../brain-runtime";
import {
  missionScopedNvdCompositionReceiptValid,
  type AutonomousCveCandidateEnrichmentPort,
  type MissionScopedNvdEnrichmentCompositionReceipt,
  type MissionScopedNvdDetailResult,
} from "../cve-intelligence";
import {
  buildRuntimeCapabilityProjection,
  createRuntimeAdapterAttestation,
  type RuntimeAdapterAttestation,
  type RuntimeSourceManifests,
  type RuntimeToolManifest,
} from "../domain";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE,
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
  AUTONOMOUS_DNS_LOCAL_PROCESS_EXECUTION_CONTRACT,
  AutonomousDnsLocalProcessExecutionFactory,
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
  AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE,
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
  AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE,
  AUTHORITATIVE_CVE_CATALOG_COMPOSITION_SCHEMA_VERSION,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_EVIDENCE_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID,
  AUTONOMOUS_VULNERABILITY_MAX_ORIGINS,
  AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT,
  AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
  AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_LOCAL_SAFE_RECON_EXECUTION_CONTRACT,
  AutonomousGeneralSafeReconExecutionFactory,
  AutonomousExploitValidationExecutionFactory,
  AutonomousLinuxPostExploitCompositePort,
  AutonomousLinuxPostExploitResultAwarePort,
  AutonomousLinuxPostExploitSessionService,
  AutonomousLinuxPrivilegeContinuationResultAwarePort,
  BoundedCandidateRuntimeLinuxPrivilegeAdapter,
  BoundedCandidateRuntimeLinuxSessionAdapter,
  CandidateLinuxPostExploitPlanExtension,
  CandidateLinuxPrivilegeContinuationRuntime,
  CandidateLinuxTransportBindingRegistry,
  MissionBrainCandidateLinuxPrivilegeContext,
  AutonomousLocalSafeReconExecutionFactory,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
  AUTONOMOUS_EXPLOIT_OUTCOME_OBSERVER_COMPOSITION_SCHEMA_VERSION,
  AUTONOMOUS_REUSABLE_EXPLOIT_MATERIALIZER_COMPOSITION_SCHEMA_VERSION,
  AutonomousReusableExploitCandidateMaterializer,
  CandidateSpecificIndependentExploitOutcomeVerifier,
  autonomousExploitOutcomeObserverCompositionReceiptValid,
  autonomousReusableExploitMaterializerCompositionReceiptValid,
  AUTONOMOUS_WHATWEB_ACTION_CLASS,
  AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_TOOL_ID,
  LocalAutonomousContractPlanner,
  LocalVerifiedEvidenceOutcomeEvaluator,
  createAutonomousLocalSafeReconPlanningPolicy,
  createAutonomousGeneralSafeReconPlanningPolicy,
  createAutonomousDnsSafeReconPlanningPolicy,
  validateAutonomousIpSafeReconConfiguration,
  validateAutonomousDnsSafeReconConfiguration,
  validateAutonomousFullTcpBaselineConfiguration,
  validateAutonomousWebSurfaceConfiguration,
  validateAutonomousCveApplicabilityConfiguration,
  validateAutonomousVulnerabilityAssessmentConfiguration,
  validateLocalAutonomousPlanningPolicy,
  withCandidateLinuxPostExploitPlanning,
  AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES,
  AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS,
  AUTONOMOUS_LINUX_SESSION_IDENTITY_BINDING_ID,
  AUTONOMOUS_LINUX_USER_FLAG_BINDING_ID,
  AUTONOMOUS_LINUX_PRIVILEGE_BINDING_ID,
  AUTONOMOUS_LINUX_ROOT_FLAG_BINDING_ID,
  AUTONOMOUS_LINUX_CLEANUP_BINDING_ID,
  autonomousEndpointDiscoveryEnabled,
  type AutonomousFullTcpPlanningConfiguration,
  type AutonomousIpSafeReconConfiguration,
  type AutonomousDnsSafeReconConfiguration,
  type AutonomousWebSurfacePlanningConfiguration,
  type AuthoritativeCveCatalogCompositionReceipt,
  type AuthoritativeCveCandidateCatalogPort,
  type AutonomousCveApplicabilityConfiguration,
  type AutonomousVulnerabilityAssessmentConfiguration,
  type AutonomousExploitOutcomeObserverCompositionPort,
  type AutonomousExploitOutcomeObserverCompositionReadiness,
  type AutonomousExploitOutcomeVerifierPort,
  type AutonomousExploitOutcomeVerifierReadinessPort,
  type AutonomousReusableExploitCandidateMaterializerPort,
  type AutonomousReusableExploitMaterializerCompositionReadiness,
  type LocalAutonomousPlanningPolicy,
} from "../autonomous-runtime";
import {
  CanonicalAutonomousExploitValidationPlanningGate,
} from "../autonomous-runtime/AutonomousExploitValidationPlanning";
import {
  type ExactTargetSandboxActivationManifest,
  type ExactTargetSandboxAttestation,
} from "../exploit-sandbox";
import type {
  LocalToolActivationReceipt,
  LocalToolCapabilityManifest,
  ReviewedLocalProcessInvocationAdapter,
} from "../local-tools";
import {
  digestCanonicalJson,
  PUBLIC_NVD_MCP_CONNECTION_ID,
  type McpCapabilityAttestation,
} from "../mcp";
import { PUBLIC_NVD_TOOL_NAME } from "../mcp-public-nvd";
import type { EngagementWorkspaceResolver } from "../system-capabilities";
import {
  FileScriptSourceStore,
  scriptSourceStoreCompositionReceiptValid,
  ScriptArtifactService,
  type ScriptSourceStoreCompositionReceipt,
  type ScriptSourceStore,
} from "../script-artifacts";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
  type TrustedLocalFileReceipt,
} from "../trusted-runtime-config";
import type { LocalGuidedToolActivationSnapshot } from "./LocalGuidedToolActivationCoordinator";
import {
  composeAutonomousWindowsIdentityProjection,
  inspectAutonomousWindowsIdentityComposition,
  type AutonomousWindowsIdentityRuntimeBinding,
} from "./AutonomousWindowsIdentityRuntimeComposition";
import {
  inspectAutonomousRuntimeComposition,
  type AutonomousRuntimeCompositionReadiness,
  type ProductionAutonomousRuntimeAdapters,
} from "./AutonomousRuntimeComposition";
import type {
  FleetAgentProjection,
  RuntimeProjectionInput,
} from "./RuntimeProjectionService";
import {
  AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
  AUTONOMOUS_NXC_SMB_SUMMARY_BINDING_ID,
  AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
  AutonomousWindowsIdentityExecutionFactory,
  withAutonomousNxcSmbSummaryPlanning,
} from "../windows-identity-tools";

export const AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION =
  "ti-scale.autonomous-dns-runtime-configuration.v1" as const;
export const LOCAL_DETERMINISTIC_PROVIDER_ATTESTATION_SCHEMA_VERSION =
  "ti-scale.local-deterministic-provider-attestation.v1" as const;
export const AUTONOMOUS_DNS_SPECIALIST_HEARTBEAT_SCHEMA_VERSION =
  "ti-scale.autonomous-dns-specialist-heartbeat.v1" as const;
export const AUTONOMOUS_EXPLOIT_VALIDATION_RUNTIME_CONFIGURATION_SCHEMA_VERSION =
  "ti-scale.autonomous-exploit-validation-runtime-configuration.v1" as const;

const AUTONOMOUS_EXPLOIT_VALIDATION_EVIDENCE_TYPES = Object.freeze([
  "exploit_validation_result",
  "finding_reproduction",
] as const);
const AUTONOMOUS_EXPLOIT_VALIDATION_RISK_CLASS_ID =
  "runtime-risk:exact-target-exploit-validation" as const;
const AUTONOMOUS_LINUX_POST_EXPLOIT_RISK_CLASS_ID =
  "runtime-risk:candidate-linux-post-exploit" as const;

export interface AutonomousExploitValidationRuntimeConfiguration {
  readonly schemaVersion:
    typeof AUTONOMOUS_EXPLOIT_VALIDATION_RUNTIME_CONFIGURATION_SCHEMA_VERSION;
  readonly configurationVersion: string;
  readonly bindingId: string;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly logicalWorkspace: string;
  readonly successCriterion: string;
}

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const VERSION = /^[A-Za-z0-9._-]{1,80}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_EXACT_TARGET_SANDBOX_ATTESTATION_LIFETIME_MS = 5 * 60_000;
const CONTROL = /[\u0000-\u001F\u007F]/u;
const SECRET = /(?:api[-_]?key|authorization|bearer|cookie|credential|password|private[-_]?key|secret|session[-_]?token)/iu;

export interface AutonomousDnsRuntimeConfiguration {
  readonly schemaVersion: typeof AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION;
  readonly configurationVersion: string;
  readonly dns: AutonomousDnsSafeReconConfiguration;
  /** Optional additive IP host-liveness and bounded service-scan route. */
  readonly ipRecon?: AutonomousIpSafeReconConfiguration;
  /** Optional exact-IP full-range TCP composite; requires ipRecon for liveness. */
  readonly fullTcpBaseline?: AutonomousFullTcpPlanningConfiguration;
  /** Optional evidence-derived HTTP metadata and WhatWeb continuation. */
  readonly webSurface?: AutonomousWebSurfacePlanningConfiguration;
  /** Optional local-only applicability phase after verified Full-TCP version evidence. */
  readonly cveApplicability?: AutonomousCveApplicabilityConfiguration;
  /** Optional fixed-template read-only assessment of verified responding HTTP origins. */
  readonly vulnerabilityAssessment?: AutonomousVulnerabilityAssessmentConfiguration;
  /** Optional exact-target, immutable-script validation inside the attested local sandbox. */
  readonly exploitValidation?: AutonomousExploitValidationRuntimeConfiguration;
  readonly localProcess: Readonly<{ readonly adapterId: string }>;
  readonly specialist: Readonly<{
    readonly id: string;
    readonly label: string;
    readonly workerId: string;
    readonly version: string;
    readonly heartbeatTtlMs: number;
  }>;
  readonly provider: Readonly<{
    readonly id: string;
    readonly label: string;
    readonly modelId: string;
    readonly modelConfigurationHash: string;
    readonly policyVersion: string;
    readonly attestationTtlMs: number;
  }>;
  /** Optional non-executing capability inventory retained for compatibility. */
  readonly mcp?: Readonly<{
    readonly id: string;
    readonly label: string;
    readonly transport: "stdio" | "streamable-http";
    readonly serverName: string;
    readonly serverVersion: string;
    readonly configurationSha256: string;
    readonly toolInputSchemaSha256: string;
  }>;
}

export interface LocalDeterministicProviderAttestation {
  readonly schemaVersion: typeof LOCAL_DETERMINISTIC_PROVIDER_ATTESTATION_SCHEMA_VERSION;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly configurationSha256: string;
  readonly policyHash: string;
  readonly plannerContractSha256: string;
  readonly evaluatorContractSha256: string;
  readonly boundary: Readonly<{
    readonly providerContact: false;
    readonly providerCredentials: false;
    readonly toolDeclarations: false;
    readonly toolDispatch: false;
    readonly deterministicPlanning: true;
    readonly verifiedEvidenceEvaluation: true;
    readonly exactTokenUsage: 0;
    readonly exactCostUsd: 0;
  }>;
  readonly attestedAt: string;
  readonly expiresAt: string;
  readonly receiptSha256: string;
}

export interface AutonomousDnsSpecialistHeartbeat {
  readonly schemaVersion: typeof AUTONOMOUS_DNS_SPECIALIST_HEARTBEAT_SCHEMA_VERSION;
  readonly specialistId: string;
  readonly workerId: string;
  readonly configurationSha256: string;
  readonly manifestSha256: string;
  readonly toolBindingSha256: string;
  readonly executableSha256: string;
  /** Present only for the additive multi-tool Safe Recon route. */
  readonly tools?: readonly Readonly<{
    readonly toolId: string;
    readonly toolBindingSha256: string;
    readonly executableSha256: string;
  }>[];
  readonly adapterContractSha256: string;
  readonly cancellation: "run_scoped_cooperative";
  readonly resultSinkBound: true;
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly receiptSha256: string;
}

export type AutonomousDnsActivationBlockerCode =
  | "trusted_configuration_invalid"
  | "scope_policy_mismatch"
  | "local_dns_tool_unavailable"
  | "local_dns_tool_receipt_stale"
  | "local_dns_executable_drift"
  | "autonomous_workspace_unavailable"
  | "second_brain_unavailable"
  | "cve_catalog_unavailable"
  | "cve_nvd_binding_unavailable"
  | "script_source_store_unavailable"
  | "exploit_materializer_unavailable"
  | "exploit_outcome_observer_unavailable"
  | "exact_target_sandbox_unavailable"
  | "exploit_component_join_invalid"
  | "candidate_linux_transport_unavailable"
  | "provider_attestation_missing"
  | "provider_attestation_invalid"
  | "provider_attestation_stale"
  | "specialist_heartbeat_missing"
  | "specialist_heartbeat_invalid"
  | "specialist_heartbeat_stale"
  | "autonomous_windows_identity_unavailable"
  | "runtime_projection_collision"
  | "autonomous_composition_blocked";

export interface AutonomousDnsActivationBlocker {
  readonly code: AutonomousDnsActivationBlockerCode;
  readonly reason: string;
  readonly remediation: string;
}

export type AutonomousDnsActivationResult =
  | Readonly<{
    readonly status: "blocked";
    readonly projection: RuntimeProjectionInput;
    readonly composition: null;
    readonly blockers: readonly AutonomousDnsActivationBlocker[];
  }>
  | Readonly<{
    readonly status: "ready";
    readonly projection: RuntimeProjectionInput;
    readonly adapters: ProductionAutonomousRuntimeAdapters;
    readonly composition: AutonomousRuntimeCompositionReadiness;
    readonly blockers: readonly [];
  }>;

type JsonRecord = Record<string, unknown>;

function plain(value: unknown, label: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return value as JsonRecord;
}

function exactKeys(value: JsonRecord, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])) {
    throw new TypeError(`${label} must contain exactly: ${canonical.join(", ")}`);
  }
}

function text(value: unknown, label: string, maximum = 500): string {
  if (typeof value !== "string" || value !== value.trim() || !value
    || value.length > maximum || CONTROL.test(value) || SECRET.test(value)) {
    throw new TypeError(`${label} must be safe non-secret text`);
  }
  return value;
}

function id(value: unknown, label: string): string {
  const result = text(value, label, 200);
  if (!PUBLIC_ID.test(result)) throw new TypeError(`${label} must be a stable public ID`);
  return result;
}

function version(value: unknown, label: string): string {
  const result = text(value, label, 80);
  if (!VERSION.test(result)) throw new TypeError(`${label} is invalid`);
  return result;
}

function hash(value: unknown, label: string): string {
  const result = text(value, label, 64);
  if (!SHA256.test(result)) throw new TypeError(`${label} must be SHA-256`);
  return result;
}

function integer(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new RangeError(`${label} must be ${minimum} through ${maximum}`);
  }
  return value as number;
}

function dnsConfiguration(value: unknown): AutonomousDnsSafeReconConfiguration {
  const record = plain(value, "dns");
  const hasAdvisoryMcp = Object.hasOwn(record, "mcpServerId");
  exactKeys(record, [
    "agentId", "bindingId", "logicalWorkspace",
    "modelConfigurationHash", "modelId", "policyId", "providerId",
    "recordType", "successCriterion",
    ...(hasAdvisoryMcp ? ["mcpServerId"] : []),
  ], "dns");
  const recordType = text(record.recordType, "dns.recordType", 16);
  if (!["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"].includes(recordType)) {
    throw new TypeError("dns.recordType is unsupported");
  }
  return Object.freeze({
    policyId: id(record.policyId, "dns.policyId"),
    bindingId: id(record.bindingId, "dns.bindingId"),
    agentId: id(record.agentId, "dns.agentId"),
    providerId: id(record.providerId, "dns.providerId"),
    modelId: id(record.modelId, "dns.modelId"),
    modelConfigurationHash: hash(record.modelConfigurationHash, "dns.modelConfigurationHash"),
    ...(hasAdvisoryMcp ? { mcpServerId: id(record.mcpServerId, "dns.mcpServerId") } : {}),
    logicalWorkspace: text(record.logicalWorkspace, "dns.logicalWorkspace", 4_096),
    recordType: recordType as AutonomousDnsSafeReconConfiguration["recordType"],
    successCriterion: text(record.successCriterion, "dns.successCriterion", 2_000),
  });
}

function ipReconConfiguration(value: unknown): AutonomousIpSafeReconConfiguration {
  const record = plain(value, "ipRecon");
  exactKeys(record, [
    "agentId", "livenessBindingId", "livenessSuccessCriterion", "logicalWorkspace",
    "modelConfigurationHash", "modelId", "policyId", "ports", "providerId",
    "serviceScanBindingId", "serviceScanSuccessCriterion",
  ], "ipRecon");
  if (!Array.isArray(record.ports)) throw new TypeError("ipRecon.ports must be an array");
  return Object.freeze({
    policyId: id(record.policyId, "ipRecon.policyId"),
    livenessBindingId: id(record.livenessBindingId, "ipRecon.livenessBindingId"),
    serviceScanBindingId: id(record.serviceScanBindingId, "ipRecon.serviceScanBindingId"),
    agentId: id(record.agentId, "ipRecon.agentId"),
    providerId: id(record.providerId, "ipRecon.providerId"),
    modelId: id(record.modelId, "ipRecon.modelId"),
    modelConfigurationHash: hash(record.modelConfigurationHash, "ipRecon.modelConfigurationHash"),
    logicalWorkspace: text(record.logicalWorkspace, "ipRecon.logicalWorkspace", 4_096),
    ports: Object.freeze(record.ports.map((port, index) =>
      integer(port, 1, 65_535, `ipRecon.ports[${index}]`))),
    livenessSuccessCriterion: text(
      record.livenessSuccessCriterion,
      "ipRecon.livenessSuccessCriterion",
      2_000,
    ),
    serviceScanSuccessCriterion: text(
      record.serviceScanSuccessCriterion,
      "ipRecon.serviceScanSuccessCriterion",
      2_000,
    ),
  });
}

function fullTcpBaselineConfiguration(value: unknown): AutonomousFullTcpPlanningConfiguration {
  const record = plain(value, "fullTcpBaseline");
  exactKeys(record, [
    "agentId", "bindingId", "logicalWorkspace", "modelConfigurationHash",
    "modelId", "policyId", "providerId", "successCriterion",
  ], "fullTcpBaseline");
  return Object.freeze({
    policyId: id(record.policyId, "fullTcpBaseline.policyId"),
    bindingId: id(record.bindingId, "fullTcpBaseline.bindingId"),
    agentId: id(record.agentId, "fullTcpBaseline.agentId"),
    providerId: id(record.providerId, "fullTcpBaseline.providerId"),
    modelId: id(record.modelId, "fullTcpBaseline.modelId"),
    modelConfigurationHash: hash(
      record.modelConfigurationHash,
      "fullTcpBaseline.modelConfigurationHash",
    ),
    logicalWorkspace: text(
      record.logicalWorkspace,
      "fullTcpBaseline.logicalWorkspace",
      4_096,
    ),
    successCriterion: text(
      record.successCriterion,
      "fullTcpBaseline.successCriterion",
      2_000,
    ),
  });
}

function webSurfaceConfiguration(value: unknown): AutonomousWebSurfacePlanningConfiguration {
  const record = plain(value, "webSurface");
  const hasEndpointBinding = Object.hasOwn(record, "endpointDiscoveryBindingId");
  const hasEndpointCriterion = Object.hasOwn(record, "endpointDiscoverySuccessCriterion");
  if (hasEndpointBinding !== hasEndpointCriterion) {
    throw new TypeError(
      "webSurface endpoint discovery requires both endpointDiscoveryBindingId and endpointDiscoverySuccessCriterion",
    );
  }
  exactKeys(record, [
    "agentId", "httpMetadataBindingId", "httpMetadataSuccessCriterion",
    "logicalWorkspace", "maximumOrigins", "modelConfigurationHash", "modelId",
    "policyId", "providerId", "whatwebBindingId", "whatwebSuccessCriterion",
    ...(hasEndpointBinding
      ? ["endpointDiscoveryBindingId", "endpointDiscoverySuccessCriterion"]
      : []),
  ], "webSurface");
  return Object.freeze({
    policyId: id(record.policyId, "webSurface.policyId"),
    httpMetadataBindingId: id(
      record.httpMetadataBindingId,
      "webSurface.httpMetadataBindingId",
    ),
    whatwebBindingId: id(record.whatwebBindingId, "webSurface.whatwebBindingId"),
    ...(hasEndpointBinding ? {
      endpointDiscoveryBindingId: id(
        record.endpointDiscoveryBindingId,
        "webSurface.endpointDiscoveryBindingId",
      ),
      endpointDiscoverySuccessCriterion: text(
        record.endpointDiscoverySuccessCriterion,
        "webSurface.endpointDiscoverySuccessCriterion",
        2_000,
      ),
    } : {}),
    agentId: id(record.agentId, "webSurface.agentId"),
    providerId: id(record.providerId, "webSurface.providerId"),
    modelId: id(record.modelId, "webSurface.modelId"),
    modelConfigurationHash: hash(
      record.modelConfigurationHash,
      "webSurface.modelConfigurationHash",
    ),
    logicalWorkspace: text(record.logicalWorkspace, "webSurface.logicalWorkspace", 4_096),
    maximumOrigins: integer(
      record.maximumOrigins,
      1,
      AUTONOMOUS_WEB_SURFACE_MAX_ORIGINS,
      "webSurface.maximumOrigins",
    ),
    httpMetadataSuccessCriterion: text(
      record.httpMetadataSuccessCriterion,
      "webSurface.httpMetadataSuccessCriterion",
      2_000,
    ),
    whatwebSuccessCriterion: text(
      record.whatwebSuccessCriterion,
      "webSurface.whatwebSuccessCriterion",
      2_000,
    ),
  });
}

function cveApplicabilityConfiguration(value: unknown): AutonomousCveApplicabilityConfiguration {
  const record = plain(value, "cveApplicability");
  exactKeys(record, [
    "agentId", "bindingId", "catalogId", "catalogSnapshotSha256",
    "maximumCandidatesPerProduct", "modelConfigurationHash", "modelId",
    "nvdEnrichment", "policyId", "providerId", "successCriterion",
  ], "cveApplicability");
  return validateAutonomousCveApplicabilityConfiguration({
    policyId: id(record.policyId, "cveApplicability.policyId"),
    bindingId: id(record.bindingId, "cveApplicability.bindingId"),
    agentId: id(record.agentId, "cveApplicability.agentId"),
    providerId: id(record.providerId, "cveApplicability.providerId"),
    modelId: id(record.modelId, "cveApplicability.modelId"),
    modelConfigurationHash: hash(
      record.modelConfigurationHash,
      "cveApplicability.modelConfigurationHash",
    ),
    catalogId: id(record.catalogId, "cveApplicability.catalogId"),
    catalogSnapshotSha256: hash(
      record.catalogSnapshotSha256,
      "cveApplicability.catalogSnapshotSha256",
    ),
    maximumCandidatesPerProduct: integer(
      record.maximumCandidatesPerProduct,
      1,
      100,
      "cveApplicability.maximumCandidatesPerProduct",
    ),
    nvdEnrichment: record.nvdEnrichment as AutonomousCveApplicabilityConfiguration["nvdEnrichment"],
    successCriterion: text(
      record.successCriterion,
      "cveApplicability.successCriterion",
      2_000,
    ),
  });
}

function vulnerabilityAssessmentConfiguration(
  value: unknown,
): AutonomousVulnerabilityAssessmentConfiguration {
  const record = plain(value, "vulnerabilityAssessment");
  exactKeys(record, [
    "agentId", "bindingId", "logicalWorkspace", "maximumOrigins",
    "modelConfigurationHash", "modelId", "policyId", "providerId",
    "schemaVersion", "successCriterion", "templatePackId",
    "templatePackSha256",
  ], "vulnerabilityAssessment");
  return Object.freeze({
    schemaVersion: text(
      record.schemaVersion,
      "vulnerabilityAssessment.schemaVersion",
      200,
    ) as AutonomousVulnerabilityAssessmentConfiguration["schemaVersion"],
    policyId: id(record.policyId, "vulnerabilityAssessment.policyId"),
    bindingId: id(record.bindingId, "vulnerabilityAssessment.bindingId"),
    agentId: id(record.agentId, "vulnerabilityAssessment.agentId"),
    providerId: id(record.providerId, "vulnerabilityAssessment.providerId"),
    modelId: id(record.modelId, "vulnerabilityAssessment.modelId"),
    modelConfigurationHash: hash(
      record.modelConfigurationHash,
      "vulnerabilityAssessment.modelConfigurationHash",
    ),
    logicalWorkspace: text(
      record.logicalWorkspace,
      "vulnerabilityAssessment.logicalWorkspace",
      4_096,
    ),
    maximumOrigins: integer(
      record.maximumOrigins,
      1,
      AUTONOMOUS_VULNERABILITY_MAX_ORIGINS,
      "vulnerabilityAssessment.maximumOrigins",
    ),
    templatePackId: text(
      record.templatePackId,
      "vulnerabilityAssessment.templatePackId",
      200,
    ) as AutonomousVulnerabilityAssessmentConfiguration["templatePackId"],
    templatePackSha256: hash(
      record.templatePackSha256,
      "vulnerabilityAssessment.templatePackSha256",
    ),
    successCriterion: text(
      record.successCriterion,
      "vulnerabilityAssessment.successCriterion",
      2_000,
    ) as AutonomousVulnerabilityAssessmentConfiguration["successCriterion"],
  });
}

function exploitValidationConfiguration(
  value: unknown,
): AutonomousExploitValidationRuntimeConfiguration {
  const record = plain(value, "exploitValidation");
  exactKeys(record, [
    "agentId", "bindingId", "configurationVersion", "logicalWorkspace",
    "modelConfigurationHash", "modelId", "providerId", "schemaVersion",
    "successCriterion",
  ], "exploitValidation");
  if (
    record.schemaVersion
      !== AUTONOMOUS_EXPLOIT_VALIDATION_RUNTIME_CONFIGURATION_SCHEMA_VERSION
  ) {
    throw new TypeError(
      "Autonomous exploit-validation runtime configuration schema is unsupported",
    );
  }
  return Object.freeze({
    schemaVersion:
      AUTONOMOUS_EXPLOIT_VALIDATION_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
    configurationVersion: version(
      record.configurationVersion,
      "exploitValidation.configurationVersion",
    ),
    bindingId: id(record.bindingId, "exploitValidation.bindingId"),
    agentId: id(record.agentId, "exploitValidation.agentId"),
    providerId: id(record.providerId, "exploitValidation.providerId"),
    modelId: id(record.modelId, "exploitValidation.modelId"),
    modelConfigurationHash: hash(
      record.modelConfigurationHash,
      "exploitValidation.modelConfigurationHash",
    ),
    logicalWorkspace: text(
      record.logicalWorkspace,
      "exploitValidation.logicalWorkspace",
      4_096,
    ),
    successCriterion: text(
      record.successCriterion,
      "exploitValidation.successCriterion",
      2_000,
    ),
  });
}

export function parseAutonomousDnsRuntimeConfiguration(value: unknown): AutonomousDnsRuntimeConfiguration {
  const record = plain(value, "Autonomous DNS runtime configuration");
  const hasAdvisoryMcp = Object.hasOwn(record, "mcp");
  const hasIpRecon = Object.hasOwn(record, "ipRecon");
  const hasFullTcpBaseline = Object.hasOwn(record, "fullTcpBaseline");
  const hasWebSurface = Object.hasOwn(record, "webSurface");
  const hasCveApplicability = Object.hasOwn(record, "cveApplicability");
  const hasVulnerabilityAssessment = Object.hasOwn(record, "vulnerabilityAssessment");
  const hasExploitValidation = Object.hasOwn(record, "exploitValidation");
  exactKeys(record, [
    "configurationVersion", "dns", "localProcess", "provider",
    "schemaVersion", "specialist",
    ...(hasIpRecon ? ["ipRecon"] : []),
    ...(hasFullTcpBaseline ? ["fullTcpBaseline"] : []),
    ...(hasWebSurface ? ["webSurface"] : []),
    ...(hasCveApplicability ? ["cveApplicability"] : []),
    ...(hasVulnerabilityAssessment ? ["vulnerabilityAssessment"] : []),
    ...(hasExploitValidation ? ["exploitValidation"] : []),
    ...(hasAdvisoryMcp ? ["mcp"] : []),
  ], "Autonomous DNS runtime configuration");
  if (record.schemaVersion !== AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION) {
    throw new TypeError("Autonomous DNS runtime configuration schema is unsupported");
  }
  const dns = dnsConfiguration(record.dns);
  const ipRecon = hasIpRecon ? ipReconConfiguration(record.ipRecon) : undefined;
  const fullTcpBaseline = hasFullTcpBaseline
    ? fullTcpBaselineConfiguration(record.fullTcpBaseline)
    : undefined;
  const webSurface = hasWebSurface
    ? webSurfaceConfiguration(record.webSurface)
    : undefined;
  const cveApplicability = hasCveApplicability
    ? cveApplicabilityConfiguration(record.cveApplicability)
    : undefined;
  const vulnerabilityAssessment = hasVulnerabilityAssessment
    ? vulnerabilityAssessmentConfiguration(record.vulnerabilityAssessment)
    : undefined;
  const exploitValidation = hasExploitValidation
    ? exploitValidationConfiguration(record.exploitValidation)
    : undefined;
  if (fullTcpBaseline && !ipRecon) {
    throw new TypeError("fullTcpBaseline requires the exact bounded ipRecon liveness configuration");
  }
  if (webSurface && (!fullTcpBaseline || !ipRecon)) {
    throw new TypeError("webSurface requires exact-IP liveness and verified Full-TCP evidence");
  }
  if (cveApplicability && (!fullTcpBaseline || !ipRecon)) {
    throw new TypeError("cveApplicability requires exact-IP liveness and verified Full-TCP version evidence");
  }
  if (vulnerabilityAssessment && (!webSurface || !fullTcpBaseline || !ipRecon)) {
    throw new TypeError(
      "vulnerabilityAssessment requires exact-IP liveness, verified Full-TCP evidence, and the responding-origin web continuation",
    );
  }
  if (exploitValidation && (!cveApplicability || !fullTcpBaseline || !ipRecon)) {
    throw new TypeError(
      "exploitValidation requires exact-IP liveness, verified Full-TCP version evidence, and CVE applicability",
    );
  }
  const localProcess = plain(record.localProcess, "localProcess");
  exactKeys(localProcess, ["adapterId"], "localProcess");
  const specialist = plain(record.specialist, "specialist");
  exactKeys(specialist, ["heartbeatTtlMs", "id", "label", "version", "workerId"], "specialist");
  const provider = plain(record.provider, "provider");
  exactKeys(provider, [
    "attestationTtlMs", "id", "label", "modelConfigurationHash", "modelId", "policyVersion",
  ], "provider");
  const mcp = hasAdvisoryMcp ? plain(record.mcp, "mcp") : undefined;
  if (mcp) {
    exactKeys(mcp, [
      "configurationSha256", "id", "label", "serverName", "serverVersion",
      "toolInputSchemaSha256", "transport",
    ], "mcp");
    if (mcp.transport !== "stdio" && mcp.transport !== "streamable-http") {
      throw new TypeError("mcp.transport is unsupported");
    }
  }
  const parsed = Object.freeze({
    schemaVersion: AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
    configurationVersion: version(record.configurationVersion, "configurationVersion"),
    dns,
    ...(ipRecon ? { ipRecon } : {}),
    ...(fullTcpBaseline ? { fullTcpBaseline } : {}),
    ...(webSurface ? { webSurface } : {}),
    ...(cveApplicability ? { cveApplicability } : {}),
    ...(vulnerabilityAssessment ? { vulnerabilityAssessment } : {}),
    ...(exploitValidation ? { exploitValidation } : {}),
    localProcess: Object.freeze({ adapterId: id(localProcess.adapterId, "localProcess.adapterId") }),
    specialist: Object.freeze({
      id: id(specialist.id, "specialist.id"),
      label: text(specialist.label, "specialist.label", 240),
      workerId: id(specialist.workerId, "specialist.workerId"),
      version: version(specialist.version, "specialist.version"),
      heartbeatTtlMs: integer(specialist.heartbeatTtlMs, 1_000, 300_000, "specialist.heartbeatTtlMs"),
    }),
    provider: Object.freeze({
      id: id(provider.id, "provider.id"),
      label: text(provider.label, "provider.label", 240),
      modelId: id(provider.modelId, "provider.modelId"),
      modelConfigurationHash: hash(provider.modelConfigurationHash, "provider.modelConfigurationHash"),
      policyVersion: version(provider.policyVersion, "provider.policyVersion"),
      attestationTtlMs: integer(provider.attestationTtlMs, 1_000, 300_000, "provider.attestationTtlMs"),
    }),
    ...(mcp ? {
      mcp: Object.freeze({
        id: id(mcp.id, "mcp.id"),
        label: text(mcp.label, "mcp.label", 240),
        transport: mcp.transport as "stdio" | "streamable-http",
        serverName: text(mcp.serverName, "mcp.serverName", 240),
        serverVersion: version(mcp.serverVersion, "mcp.serverVersion"),
        configurationSha256: hash(mcp.configurationSha256, "mcp.configurationSha256"),
        toolInputSchemaSha256: hash(mcp.toolInputSchemaSha256, "mcp.toolInputSchemaSha256"),
      }),
    } : {}),
  } satisfies AutonomousDnsRuntimeConfiguration);
  if (parsed.dns.agentId !== parsed.specialist.id
    || parsed.dns.providerId !== parsed.provider.id
    || parsed.dns.modelId !== parsed.provider.modelId
    || parsed.dns.modelConfigurationHash !== parsed.provider.modelConfigurationHash
    || ((parsed.dns.mcpServerId !== undefined || parsed.mcp !== undefined)
      && parsed.dns.mcpServerId !== parsed.mcp?.id)) {
    throw new TypeError("Autonomous DNS stable IDs drift across the trusted configuration");
  }
  if (parsed.ipRecon && (
    parsed.ipRecon.policyId !== parsed.dns.policyId
    || parsed.ipRecon.agentId !== parsed.specialist.id
    || parsed.ipRecon.providerId !== parsed.provider.id
    || parsed.ipRecon.modelId !== parsed.provider.modelId
    || parsed.ipRecon.modelConfigurationHash !== parsed.provider.modelConfigurationHash
  )) {
    throw new TypeError("Autonomous IP stable IDs drift across the trusted configuration");
  }
  if (parsed.fullTcpBaseline && (
    parsed.fullTcpBaseline.policyId !== parsed.dns.policyId
    || parsed.fullTcpBaseline.agentId !== parsed.specialist.id
    || parsed.fullTcpBaseline.providerId !== parsed.provider.id
    || parsed.fullTcpBaseline.modelId !== parsed.provider.modelId
    || parsed.fullTcpBaseline.modelConfigurationHash !== parsed.provider.modelConfigurationHash
  )) {
    throw new TypeError("Autonomous Full-TCP stable IDs drift across the trusted configuration");
  }
  if (parsed.webSurface && (
    parsed.webSurface.policyId !== parsed.dns.policyId
    || parsed.webSurface.agentId !== parsed.specialist.id
    || parsed.webSurface.providerId !== parsed.provider.id
    || parsed.webSurface.modelId !== parsed.provider.modelId
    || parsed.webSurface.modelConfigurationHash !== parsed.provider.modelConfigurationHash
    || parsed.webSurface.logicalWorkspace !== parsed.fullTcpBaseline?.logicalWorkspace
  )) {
    throw new TypeError("Autonomous web-surface stable IDs drift across the trusted configuration");
  }
  if (parsed.cveApplicability && (
    parsed.cveApplicability.policyId !== parsed.dns.policyId
    || parsed.cveApplicability.agentId !== parsed.specialist.id
    || parsed.cveApplicability.providerId !== parsed.provider.id
    || parsed.cveApplicability.modelId !== parsed.provider.modelId
    || parsed.cveApplicability.modelConfigurationHash !== parsed.provider.modelConfigurationHash
  )) {
    throw new TypeError("Autonomous CVE applicability stable IDs drift across the trusted configuration");
  }
  if (parsed.vulnerabilityAssessment && (
    parsed.vulnerabilityAssessment.policyId !== parsed.dns.policyId
    || parsed.vulnerabilityAssessment.agentId !== parsed.specialist.id
    || parsed.vulnerabilityAssessment.providerId !== parsed.provider.id
    || parsed.vulnerabilityAssessment.modelId !== parsed.provider.modelId
    || parsed.vulnerabilityAssessment.modelConfigurationHash
      !== parsed.provider.modelConfigurationHash
    || parsed.vulnerabilityAssessment.logicalWorkspace
      !== parsed.fullTcpBaseline?.logicalWorkspace
  )) {
    throw new TypeError(
      "Autonomous vulnerability-assessment stable IDs drift across the trusted configuration",
    );
  }
  if (parsed.exploitValidation && (
    parsed.exploitValidation.agentId !== parsed.specialist.id
    || parsed.exploitValidation.providerId !== parsed.provider.id
    || parsed.exploitValidation.modelId !== parsed.provider.modelId
    || parsed.exploitValidation.modelConfigurationHash
      !== parsed.provider.modelConfigurationHash
    || parsed.exploitValidation.logicalWorkspace
      !== parsed.fullTcpBaseline?.logicalWorkspace
  )) {
    throw new TypeError(
      "Autonomous exploit validation must share the exact Safe Recon workspace, specialist, provider, and model identity",
    );
  }
  return parsed;
}

export function loadTrustedAutonomousDnsRuntimeConfiguration(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<AutonomousDnsRuntimeConfiguration> {
  if (reference.maximumBytes !== undefined && reference.maximumBytes > 256 * 1_024) {
    throw new RangeError("Autonomous DNS trusted configuration exceeds its 262144-byte boundary");
  }
  return loadTrustedJson(
    { ...reference, maximumBytes: reference.maximumBytes ?? 256 * 1_024 },
    parseAutonomousDnsRuntimeConfiguration,
  );
}

/**
 * Builds the one deterministic planning policy represented by the trusted
 * runtime document. Exploit validation is additive and has no generic command
 * surface: the canonical mission gate replaces its arguments only after an
 * approved ScriptArtifact, current evidence, and active-Vault procedure match.
 */
export function createConfiguredAutonomousPlanningPolicy(
  configuration: AutonomousDnsRuntimeConfiguration,
  manifest: LocalToolCapabilityManifest,
  candidateLinuxTransportReady = false,
  autonomousWindowsIdentity?: Readonly<{
    logicalWorkspace: string;
  }>,
): LocalAutonomousPlanningPolicy {
  const base = configuration.fullTcpBaseline && configuration.ipRecon
    ? createAutonomousGeneralSafeReconPlanningPolicy(
        configuration.dns,
        configuration.ipRecon,
        configuration.fullTcpBaseline,
        manifest,
        configuration.webSurface,
        configuration.cveApplicability,
        configuration.vulnerabilityAssessment,
      )
    : configuration.ipRecon
      ? createAutonomousLocalSafeReconPlanningPolicy(
          configuration.dns,
          configuration.ipRecon,
          manifest,
        )
      : createAutonomousDnsSafeReconPlanningPolicy(
          configuration.dns,
          manifest,
        );
  const exploit = configuration.exploitValidation;
  let complete: LocalAutonomousPlanningPolicy;
  if (!exploit) {
    if (candidateLinuxTransportReady) {
      throw new TypeError(
        "Candidate Linux post-exploit planning requires exploit validation",
      );
    }
    complete = base;
  } else {
    if (!configuration.cveApplicability || !configuration.fullTcpBaseline) {
      throw new TypeError(
        "Exploit validation cannot be planned without the verified version/CVE sequence",
      );
    }
    const exploitPolicy = validateLocalAutonomousPlanningPolicy({
      ...base,
      maximumSteps: base.maximumSteps + 1,
      bindings: Object.freeze([
        ...base.bindings,
        Object.freeze({
          bindingId: exploit.bindingId,
          actionClassId: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
          targetKinds: Object.freeze(["ip"] as const),
          phase: "exact_target_exploit_validation",
          title: "Validate one evidence-matched weakness in the disposable lab",
          objective:
            "Run one approved, tested Python ScriptArtifact against the exact disposable target named in the signed contract.",
          explanation:
            "Ti-Scale selects only a current-run script whose product version and confirmed CVE match the target, whose reusable procedure is synchronized to the active Vault, and whose tests all passed.",
          rationale:
            "The script runs without credentials or a public model inside an independently attested cgroup and Bubblewrap boundary that permits egress only to the exact authorized IP.",
          successCriteria: Object.freeze([exploit.successCriterion]),
          reversibility:
            "The runtime creates no persistence, transports no credentials, writes only to its confined job workspace, bounds time/output, and preserves a cancellation receipt. Target-side effects remain those documented by the approved ScriptArtifact.",
          riskClass: "high" as const,
          idempotent: false,
          destructive: false,
          agentId: exploit.agentId,
          providerId: exploit.providerId,
          modelId: exploit.modelId,
          modelConfigurationHash: exploit.modelConfigurationHash,
          executionBinding: "reviewed_local_process" as const,
          toolId: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
          targetParameter: "target",
          staticParameters: Object.freeze({}),
          capabilityIds: Object.freeze([
            `capability:${AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE}`,
          ]),
          requiredEvidenceTypeIds:
            AUTONOMOUS_EXPLOIT_VALIDATION_EVIDENCE_TYPES,
        }),
      ]),
    });
    complete = candidateLinuxTransportReady
      ? withCandidateLinuxPostExploitPlanning(exploitPolicy, {
          agentId: exploit.agentId,
          providerId: exploit.providerId,
          modelId: exploit.modelId,
          modelConfigurationHash: exploit.modelConfigurationHash,
        })
      : exploitPolicy;
  }
  return autonomousWindowsIdentity
    ? withAutonomousNxcSmbSummaryPlanning(complete, {
        logicalWorkspace: autonomousWindowsIdentity.logicalWorkspace,
        providerId: configuration.provider.id,
        modelId: configuration.provider.modelId,
        modelConfigurationHash:
          configuration.provider.modelConfigurationHash,
      })
    : complete;
}

const CANONICAL_UTC_ATTESTATION_TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

function validTime(value: string): number | null {
  if (!CANONICAL_UTC_ATTESTATION_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  const canonical = new Date(parsed).toISOString();
  const wholeSecond = canonical.endsWith(".000Z")
    ? canonical.replace(".000Z", "Z")
    : canonical;
  return value === canonical || value === wholeSecond ? parsed : null;
}

function trustedReceiptValid(loaded: LoadedTrustedJson<AutonomousDnsRuntimeConfiguration>): boolean {
  const receipt = loaded.receipt;
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  return receipt.schemaVersion === "ti-scale.trusted-local-file-receipt.v1"
    && SHA256.test(receipt.sourceSha256)
    && receipt.canonicalSha256 === digestCanonicalJson(
      loaded.value,
      { maxBytes: 256 * 1_024, maxDepth: 24 },
    ).sha256
    && receipt.sourcePath.startsWith(`${receipt.trustRoot}/`)
    && receipt.byteSize >= 2 && receipt.byteSize <= 256 * 1_024
    && (receipt.ownerUid === 0 || receipt.ownerUid === currentUid)
    && (receipt.mode & 0o022) === 0 && (receipt.mode & 0o7111) === 0
    && /^\d+$/u.test(receipt.device) && /^\d+$/u.test(receipt.inode);
}

function receiptDigest<T extends { readonly receiptSha256: string }>(receipt: T): string {
  const { receiptSha256: _ignored, ...unsigned } = receipt;
  return digestCanonicalJson(unsigned, { maxBytes: 512 * 1_024, maxDepth: 24 }).sha256;
}

/** Content-free local provider attestation; no model, provider, target, or tool is contacted. */
export function attestLocalDeterministicAutonomousDnsProvider(input: Readonly<{
  configuration: LoadedTrustedJson<AutonomousDnsRuntimeConfiguration>;
  planner: LocalAutonomousContractPlanner;
  evaluator: LocalVerifiedEvidenceOutcomeEvaluator;
  candidateLinuxTransportReady?: boolean;
  autonomousWindowsIdentity?: Readonly<{ logicalWorkspace: string }>;
  now?: Date;
}>): LocalDeterministicProviderAttestation {
  if (!trustedReceiptValid(input.configuration)) {
    throw new Error("The local provider cannot attest an untrusted Autonomous DNS configuration");
  }
  const config = input.configuration.value;
  const now = input.now ?? new Date();
  const bindings = input.planner.localPlanningBoundary.bindings;
  const expectedBindings = expectedPlannerBindings(
    config,
    input.candidateLinuxTransportReady === true,
    input.autonomousWindowsIdentity !== undefined,
  );
  const exactBindingsMatch = bindings.length === expectedBindings.length
    && expectedBindings.every((expected) => bindings.filter((binding) =>
      binding.bindingId === expected.bindingId
      && "toolId" in binding
      && binding.toolId === expected.toolId).length === 1);
  if (!Number.isFinite(now.getTime())
    || input.planner.localPlanningBoundary.policyId !== config.dns.policyId
    || !exactBindingsMatch
    || bindings.some((binding) =>
      binding.providerId !== config.provider.id
      || binding.modelId !== config.provider.modelId
      || binding.modelConfigurationHash !== config.provider.modelConfigurationHash)
    || input.evaluator.autonomousContract.providerContact !== false) {
    throw new Error("The local deterministic provider objects do not match the trusted policy");
  }
  const unsigned = {
    schemaVersion: LOCAL_DETERMINISTIC_PROVIDER_ATTESTATION_SCHEMA_VERSION,
    providerId: config.provider.id,
    modelId: config.provider.modelId,
    modelConfigurationHash: config.provider.modelConfigurationHash,
    configurationSha256: input.configuration.receipt.canonicalSha256,
    policyHash: input.planner.localPlanningBoundary.policyHash,
    plannerContractSha256: digestCanonicalJson(input.planner.autonomousContract, {
      maxBytes: 16 * 1_024, maxDepth: 8,
    }).sha256,
    evaluatorContractSha256: digestCanonicalJson(input.evaluator.autonomousContract, {
      maxBytes: 16 * 1_024, maxDepth: 8,
    }).sha256,
    boundary: {
      providerContact: false as const,
      providerCredentials: false as const,
      toolDeclarations: false as const,
      toolDispatch: false as const,
      deterministicPlanning: true as const,
      verifiedEvidenceEvaluation: true as const,
      exactTokenUsage: 0 as const,
      exactCostUsd: 0 as const,
    },
    attestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + config.provider.attestationTtlMs).toISOString(),
  };
  return Object.freeze({
    ...unsigned,
    receiptSha256: digestCanonicalJson(unsigned, { maxBytes: 512 * 1_024, maxDepth: 24 }).sha256,
  });
}

/**
 * Planner authority is attested by exact configured binding/tool identity.
 * Physical phase tools remain separately attested by the specialist
 * heartbeat; this list contains only the virtual actions the planner may
 * place in a mission plan.
 */
function expectedPlannerBindings(
  configuration: AutonomousDnsRuntimeConfiguration,
  candidateLinuxTransportReady = false,
  autonomousWindowsIdentityReady = false,
): readonly Readonly<{ readonly bindingId: string; readonly toolId: string }>[] {
  return Object.freeze([
    Object.freeze({
      bindingId: configuration.dns.bindingId,
      toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    }),
    ...(configuration.ipRecon ? [Object.freeze({
      bindingId: configuration.ipRecon.livenessBindingId,
      toolId: AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    }), configuration.fullTcpBaseline ? Object.freeze({
      bindingId: configuration.fullTcpBaseline.bindingId,
      toolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    }) : Object.freeze({
      bindingId: configuration.ipRecon.serviceScanBindingId,
      toolId: AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
    })] : []),
    ...(configuration.webSurface ? [Object.freeze({
      bindingId: configuration.webSurface.httpMetadataBindingId,
      toolId: AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
    }), Object.freeze({
      bindingId: configuration.webSurface.whatwebBindingId,
      toolId: AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
    }), ...(autonomousEndpointDiscoveryEnabled(configuration.webSurface)
      ? [Object.freeze({
          bindingId: configuration.webSurface.endpointDiscoveryBindingId,
          toolId: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
        })]
      : [])] : []),
    ...(configuration.cveApplicability ? [Object.freeze({
      bindingId: configuration.cveApplicability.bindingId,
      toolId: AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
    })] : []),
    ...(configuration.vulnerabilityAssessment ? [Object.freeze({
      bindingId: configuration.vulnerabilityAssessment.bindingId,
      toolId: AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
    })] : []),
    ...(configuration.exploitValidation ? [Object.freeze({
      bindingId: configuration.exploitValidation.bindingId,
      toolId: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
    })] : []),
    ...(candidateLinuxTransportReady ? [
      Object.freeze({
        bindingId: AUTONOMOUS_LINUX_SESSION_IDENTITY_BINDING_ID,
        toolId: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[0],
      }),
      Object.freeze({
        bindingId: AUTONOMOUS_LINUX_USER_FLAG_BINDING_ID,
        toolId: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[1],
      }),
      Object.freeze({
        bindingId: AUTONOMOUS_LINUX_PRIVILEGE_BINDING_ID,
        toolId: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[2],
      }),
      Object.freeze({
        bindingId: AUTONOMOUS_LINUX_ROOT_FLAG_BINDING_ID,
        toolId: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[3],
      }),
      Object.freeze({
        bindingId: AUTONOMOUS_LINUX_CLEANUP_BINDING_ID,
        toolId: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[4],
      }),
    ] : []),
    ...(autonomousWindowsIdentityReady ? [Object.freeze({
      bindingId: AUTONOMOUS_NXC_SMB_SUMMARY_BINDING_ID,
      toolId: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    })] : []),
  ]);
}

export function attestAutonomousDnsSpecialistHeartbeat(input: Readonly<{
  configuration: LoadedTrustedJson<AutonomousDnsRuntimeConfiguration>;
  manifest: LocalToolCapabilityManifest;
  activationReceipt: LocalToolActivationReceipt;
  activationReceipts?: readonly LocalToolActivationReceipt[];
  adapterContract: typeof AUTONOMOUS_DNS_LOCAL_PROCESS_EXECUTION_CONTRACT
    | typeof AUTONOMOUS_LOCAL_SAFE_RECON_EXECUTION_CONTRACT
    | typeof AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT;
  now?: Date;
}>): AutonomousDnsSpecialistHeartbeat {
  if (!trustedReceiptValid(input.configuration)) {
    throw new Error("The specialist cannot attest an untrusted Autonomous DNS configuration");
  }
  const config = input.configuration.value;
  const toolIds = requiredToolIds(config);
  const activationReceipts = input.activationReceipts ?? [input.activationReceipt];
  const tools = toolIds.map((toolId) => {
    const tool = input.manifest.resolve(toolId);
    const activation = activationReceipts.filter((receipt) => receipt.toolId === toolId);
    if (!tool || activation.length !== 1
      || activation[0]!.bindingSha256 !== tool.bindingSha256
      || activation[0]!.executableSha256 !== tool.executable.expectedSha256) {
      throw new Error("The specialist heartbeat inputs do not match every reviewed Safe Recon binding");
    }
    return Object.freeze({
      toolId,
      toolBindingSha256: tool.bindingSha256,
      executableSha256: tool.executable.expectedSha256,
    });
  });
  const dnsTool = tools[0]!;
  const expectedAdapterId = config.fullTcpBaseline
    ? AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID
    : config.ipRecon ? AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID
    : AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID;
  if (input.adapterContract.adapterId !== expectedAdapterId
    || input.adapterContract.executionBinding !== "reviewed_local_process"
    || input.adapterContract.directArgv !== true
    || input.adapterContract.shell !== false
    || input.adapterContract.cancellation !== "run_scoped_cooperative") {
    throw new Error("The specialist heartbeat inputs do not match the reviewed Safe Recon binding");
  }
  const now = input.now ?? new Date();
  if (!Number.isFinite(now.getTime())) throw new RangeError("Specialist heartbeat time is invalid");
  const unsigned = {
    schemaVersion: AUTONOMOUS_DNS_SPECIALIST_HEARTBEAT_SCHEMA_VERSION,
    specialistId: config.specialist.id,
    workerId: config.specialist.workerId,
    configurationSha256: input.configuration.receipt.canonicalSha256,
    manifestSha256: input.manifest.descriptor.manifestSha256,
    toolBindingSha256: dnsTool.toolBindingSha256,
    executableSha256: dnsTool.executableSha256,
    ...(config.ipRecon ? { tools: Object.freeze(tools) } : {}),
    adapterContractSha256: digestCanonicalJson(input.adapterContract, {
      maxBytes: 16 * 1_024, maxDepth: 8,
    }).sha256,
    cancellation: "run_scoped_cooperative" as const,
    resultSinkBound: true as const,
    observedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + config.specialist.heartbeatTtlMs).toISOString(),
  };
  return Object.freeze({
    ...unsigned,
    receiptSha256: digestCanonicalJson(unsigned, { maxBytes: 512 * 1_024, maxDepth: 24 }).sha256,
  });
}

function blocker(
  code: AutonomousDnsActivationBlockerCode,
  reason: string,
  remediation: string,
): AutonomousDnsActivationBlocker {
  return Object.freeze({ code, reason, remediation });
}

function exactActivationReceipt(snapshot: LocalGuidedToolActivationSnapshot): LocalToolActivationReceipt | undefined {
  const matches = snapshot.activationReceipts.filter(({ toolId }) => toolId === AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID);
  return matches.length === 1 ? matches[0] : undefined;
}

function requiredToolIds(configuration: AutonomousDnsRuntimeConfiguration): readonly string[] {
  return configuration.webSurface ? Object.freeze([
    AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    AUTONOMOUS_HTTP_METADATA_TOOL_ID,
    AUTONOMOUS_WHATWEB_TOOL_ID,
    ...(autonomousEndpointDiscoveryEnabled(configuration.webSurface)
      ? [AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID]
      : []),
    ...(configuration.vulnerabilityAssessment
      ? [AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID]
      : []),
  ]) : configuration.fullTcpBaseline ? Object.freeze([
    AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  ]) : configuration.ipRecon ? Object.freeze([
    AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  ]) : Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID]);
}

function authorizedPlannerToolIds(
  configuration: AutonomousDnsRuntimeConfiguration,
  candidateLinuxTransportReady = false,
): readonly string[] {
  const physicalOrComposite = configuration.webSurface ? [
    AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
    AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
    ...(autonomousEndpointDiscoveryEnabled(configuration.webSurface)
      ? [AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE]
      : []),
  ] : configuration.fullTcpBaseline ? [
    AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  ] : [...requiredToolIds(configuration)];
  return Object.freeze([
    ...physicalOrComposite,
    ...(configuration.cveApplicability
      ? [AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE]
      : []),
    ...(configuration.vulnerabilityAssessment
      ? [AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE]
      : []),
    ...(configuration.exploitValidation
      ? [AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE]
      : []),
    ...(candidateLinuxTransportReady
      ? [...AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS]
      : []),
  ]);
}

/** Exact action-class set that must survive the final Autonomous composition. */
export function requiredAutonomousSafeReconActionClassIds(
  configuration: AutonomousDnsRuntimeConfiguration,
  candidateLinuxTransportReady = false,
): readonly string[] {
  return configuration.ipRecon ? Object.freeze([
    AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
    AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
    configuration.fullTcpBaseline
      ? AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS
      : AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
    ...(configuration.webSurface ? [
      AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
      AUTONOMOUS_WHATWEB_ACTION_CLASS,
      ...(autonomousEndpointDiscoveryEnabled(configuration.webSurface)
        ? [AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS]
        : []),
    ] : []),
    ...(configuration.cveApplicability
      ? [AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS]
      : []),
    ...(configuration.vulnerabilityAssessment
      ? [AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS]
      : []),
    ...(configuration.exploitValidation
      ? [AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS]
      : []),
    ...(candidateLinuxTransportReady
      ? [...AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES]
      : []),
  ]) : Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS]);
}

function exactActivationReceipts(
  snapshot: LocalGuidedToolActivationSnapshot,
  configuration: AutonomousDnsRuntimeConfiguration,
): readonly LocalToolActivationReceipt[] | undefined {
  const receipts = requiredToolIds(configuration).map((toolId) => {
    const matches = snapshot.activationReceipts.filter((receipt) => receipt.toolId === toolId);
    return matches.length === 1 ? matches[0] : undefined;
  });
  return receipts.every((receipt) => receipt !== undefined)
    ? Object.freeze(receipts as LocalToolActivationReceipt[])
    : undefined;
}

function appendUnique<T extends { readonly id: string }>(
  label: string,
  existing: readonly T[],
  addition: T,
): readonly T[] {
  if (existing.some(({ id: current }) => current === addition.id)) {
    throw new Error(`${label} stable ID collision: ${addition.id}`);
  }
  return Object.freeze([...existing, addition]);
}

function sameStableIds(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const expected = new Set(right);
  return expected.size === right.length && left.every((id) => expected.has(id));
}

function sameRuntimeAdapterAttestation(
  left: RuntimeAdapterAttestation | undefined,
  right: RuntimeAdapterAttestation | undefined,
): boolean {
  return left === undefined
    ? right === undefined
    : right !== undefined
      && left.schemaVersion === right.schemaVersion
      && left.source === right.source
      && left.toolId === right.toolId
      && left.dependencyId === right.dependencyId
      && left.parentBindingSha256 === right.parentBindingSha256
      && left.bindingSha256 === right.bindingSha256
      && left.observedAt === right.observedAt
      && left.expiresAt === right.expiresAt
      && left.receiptSha256 === right.receiptSha256;
}

function sameRuntimeAdapterDependencies(
  left: RuntimeToolManifest["dependencies"],
  right: RuntimeToolManifest["dependencies"],
): boolean {
  const leftDependencies = left ?? [];
  const rightDependencies = right ?? [];
  if (leftDependencies.length !== rightDependencies.length) return false;
  const leftById = new Map(leftDependencies.map((dependency) => [
    dependency.id,
    dependency,
  ]));
  return leftById.size === leftDependencies.length
    && rightDependencies.every((dependency) => {
      const existing = leftById.get(dependency.id);
      return existing?.ready === dependency.ready
        && existing.attestation === undefined
        && dependency.attestation === undefined
        && sameRuntimeAdapterAttestation(
          existing.runtimeAdapterAttestation,
          dependency.runtimeAdapterAttestation,
        );
    });
}

type AutonomousExploitOutcomeObserverPort =
  & AutonomousExploitOutcomeObserverCompositionPort
  & AutonomousExploitOutcomeVerifierPort
  & AutonomousExploitOutcomeVerifierReadinessPort;

type AttestedAutonomousCveNvdEnrichmentPort =
  & AutonomousCveCandidateEnrichmentPort<MissionScopedNvdDetailResult>
  & Readonly<{
    inspectComposition():
      MissionScopedNvdEnrichmentCompositionReceipt | undefined;
  }>;

interface AutonomousCveRuntimeComposition {
  readonly catalog: AuthoritativeCveCatalogCompositionReceipt;
  readonly nvd?: MissionScopedNvdEnrichmentCompositionReceipt;
}

function authoritativeCveCatalogCompositionValid(
  receipt: AuthoritativeCveCatalogCompositionReceipt,
  configuration: AutonomousCveApplicabilityConfiguration,
): boolean {
  try {
    const { receiptSha256, ...unsigned } = receipt;
    return receipt.schemaVersion
        === AUTHORITATIVE_CVE_CATALOG_COMPOSITION_SCHEMA_VERSION
      && receipt.catalogId === configuration.catalogId
      && receipt.catalogSnapshotSha256
        === configuration.catalogSnapshotSha256
      && receipt.maximumCandidatesPerProduct
        === configuration.maximumCandidatesPerProduct
      && receipt.localReadOnly === true
      && receipt.targetInteraction === false
      && receipt.executionAuthority === "none"
      && /^[a-f0-9]{64}$/u.test(receiptSha256)
      && receiptSha256 === digestCanonicalJson(unsigned, {
        maxBytes: 64 * 1_024,
        maxDepth: 12,
      }).sha256;
  } catch {
    return false;
  }
}

function autonomousCveRuntimeCompositionValid(
  composition: AutonomousCveRuntimeComposition | undefined,
  configuration: AutonomousCveApplicabilityConfiguration,
  now: Date,
): boolean {
  if (!composition
    || !authoritativeCveCatalogCompositionValid(
      composition.catalog,
      configuration,
    )) return false;
  if (configuration.nvdEnrichment === "disabled") {
    return composition.nvd === undefined;
  }
  return Boolean(
    composition.nvd
    && composition.nvd.connectionId === PUBLIC_NVD_MCP_CONNECTION_ID
    && composition.nvd.toolName === PUBLIC_NVD_TOOL_NAME
    && missionScopedNvdCompositionReceiptValid(composition.nvd, now),
  );
}

interface AutonomousExploitPathCompositionReadiness {
  readonly ready: boolean;
  readonly candidateMaterializerReady: boolean;
  readonly independentOutcomeObserverReady: boolean;
  readonly exactTargetSandboxReady: boolean;
  readonly scriptSourceStoreReady: boolean;
  readonly brainContextReady: boolean;
  readonly exactComponentJoinReady: boolean;
  readonly candidateMaterializerReceipt?:
    AutonomousReusableExploitMaterializerCompositionReadiness;
  readonly outcomeObserverReceipt?:
    AutonomousExploitOutcomeObserverCompositionReadiness;
  readonly scriptSourceStoreReceipt?: ScriptSourceStoreCompositionReceipt;
  readonly brainContextReceipt?: BrainContextServiceCompositionReceipt;
}

function inspectExploitPathComposition(input: Readonly<{
  database?: SqliteDatabase;
  configuration: AutonomousDnsRuntimeConfiguration;
  candidateMaterializer?: AutonomousReusableExploitCandidateMaterializerPort;
  outcomeObserver?: AutonomousExploitOutcomeObserverPort;
  exploitSandboxAttestation?: ExactTargetSandboxAttestation;
  scriptSourceStore?: ScriptSourceStore;
  brainContext?: BrainContextService;
  now: Date;
}>): AutonomousExploitPathCompositionReadiness {
  if (!input.configuration.exploitValidation) {
    return Object.freeze({
      ready: false,
      candidateMaterializerReady: false,
      independentOutcomeObserverReady: false,
      exactTargetSandboxReady: false,
      scriptSourceStoreReady: false,
      brainContextReady: false,
      exactComponentJoinReady: false,
    });
  }
  let candidateMaterializerReady = false;
  let independentOutcomeObserverReady = false;
  let candidateMaterializerReceipt:
    AutonomousReusableExploitMaterializerCompositionReadiness | undefined;
  let outcomeObserverReceipt:
    AutonomousExploitOutcomeObserverCompositionReadiness | undefined;
  try {
    const receipt = input.candidateMaterializer?.inspectComposition(input.now);
    candidateMaterializerReady = Boolean(
      receipt
      && input.candidateMaterializer
        instanceof AutonomousReusableExploitCandidateMaterializer
      && receipt.schemaVersion
        === AUTONOMOUS_REUSABLE_EXPLOIT_MATERIALIZER_COMPOSITION_SCHEMA_VERSION
      && autonomousReusableExploitMaterializerCompositionReceiptValid(
        receipt,
        input.now,
      )
      && typeof input.candidateMaterializer?.materialize === "function",
    );
    if (candidateMaterializerReady && receipt) {
      candidateMaterializerReceipt = receipt;
    }
  } catch {
    candidateMaterializerReady = false;
    candidateMaterializerReceipt = undefined;
  }
  try {
    const receipt = input.outcomeObserver?.inspectComposition(input.now);
    independentOutcomeObserverReady = Boolean(
      receipt
      && input.outcomeObserver
        instanceof CandidateSpecificIndependentExploitOutcomeVerifier
      && receipt.schemaVersion
        === AUTONOMOUS_EXPLOIT_OUTCOME_OBSERVER_COMPOSITION_SCHEMA_VERSION
      && autonomousExploitOutcomeObserverCompositionReceiptValid(
        receipt,
        input.now,
      )
      && receipt.ready === true
      && typeof receipt.observerId === "string"
      && PUBLIC_ID.test(receipt.observerId)
      && receipt.candidateSpecific === true
      && receipt.independentTargetImpact === true
      && receipt.custodyVerifiedEvidence === true
      && receipt.rawOutputAuthority === "none"
      && receipt.grantsMissionExecution === false
      && typeof input.outcomeObserver?.inspect === "function"
      && typeof input.outcomeObserver?.verify === "function",
    );
    if (independentOutcomeObserverReady && receipt) {
      outcomeObserverReceipt = receipt;
    }
  } catch {
    independentOutcomeObserverReady = false;
    outcomeObserverReceipt = undefined;
  }
  const exactTargetSandboxReady = Boolean(input.exploitSandboxAttestation);
  let scriptSourceStoreReceipt: ScriptSourceStoreCompositionReceipt | undefined;
  let brainContextReceipt: BrainContextServiceCompositionReceipt | undefined;
  try {
    const receipt = input.scriptSourceStore
      instanceof FileScriptSourceStore
      ? input.scriptSourceStore.inspectComposition(input.now)
      : undefined;
    if (
      receipt
      && receipt.storeId === "file-content-addressed-v1"
      && receipt.localFilesystem === true
      && scriptSourceStoreCompositionReceiptValid(receipt, input.now)
    ) {
      scriptSourceStoreReceipt = receipt;
    }
  } catch {
    scriptSourceStoreReceipt = undefined;
  }
  try {
    const receipt = input.brainContext instanceof BrainContextService
      ? input.brainContext.inspectComposition(input.now)
      : undefined;
    if (receipt && brainContextServiceCompositionReceiptValid(receipt, input.now)) {
      brainContextReceipt = receipt;
    }
  } catch {
    brainContextReceipt = undefined;
  }
  const scriptSourceStoreReady = Boolean(scriptSourceStoreReceipt);
  const brainContextReady = Boolean(brainContextReceipt);
  const databaseIdentity = input.database
    ? inspectCanonicalDatabaseIdentity(input.database)
    : undefined;
  const exactComponentJoinReady = Boolean(
    databaseIdentity
    && candidateMaterializerReceipt
    && outcomeObserverReceipt
    && scriptSourceStoreReceipt
    && brainContextReceipt
    && candidateMaterializerReceipt.databaseIdentitySha256
      === databaseIdentity.databaseIdentitySha256
    && outcomeObserverReceipt.databaseIdentitySha256
      === databaseIdentity.databaseIdentitySha256
    && brainContextReceipt.databaseIdentitySha256
      === databaseIdentity.databaseIdentitySha256
    && candidateMaterializerReceipt.databaseMigrationVersion
      === databaseIdentity.migrationVersion
    && outcomeObserverReceipt.databaseMigrationVersion
      === databaseIdentity.migrationVersion
    && brainContextReceipt.databaseMigrationVersion
      === databaseIdentity.migrationVersion
    && candidateMaterializerReceipt.scriptSourceStoreReceiptSha256
      === scriptSourceStoreReceipt.receiptSha256
    && candidateMaterializerReceipt.brainContextReceiptSha256
      === brainContextReceipt.receiptSha256
    && candidateMaterializerReceipt.receiptSha256
      !== outcomeObserverReceipt.receiptSha256
  );
  return Object.freeze({
    ready:
      candidateMaterializerReady
      && independentOutcomeObserverReady
      && exactTargetSandboxReady
      && scriptSourceStoreReady
      && brainContextReady
      && exactComponentJoinReady,
    candidateMaterializerReady,
    independentOutcomeObserverReady,
    exactTargetSandboxReady,
    scriptSourceStoreReady,
    brainContextReady,
    exactComponentJoinReady,
    ...(candidateMaterializerReceipt
      ? { candidateMaterializerReceipt }
      : {}),
    ...(outcomeObserverReceipt
      ? { outcomeObserverReceipt }
      : {}),
    ...(scriptSourceStoreReceipt ? { scriptSourceStoreReceipt } : {}),
    ...(brainContextReceipt ? { brainContextReceipt } : {}),
  });
}

function runtimeAdapterAttestation(input: Readonly<{
  toolId: string;
  dependencyId?: string;
  parentBindingSha256?: string;
  executionJourneys: readonly ("autonomous" | "guided")[];
  observedAt: readonly string[];
  expiresAt: readonly string[];
  binding: RuntimeAdapterAttestation["binding"];
}>): RuntimeAdapterAttestation {
  const observedTimes = input.observedAt.map(validTime);
  const expiryTimes = input.expiresAt.map(validTime);
  if (observedTimes.some((value) => value === null)
    || expiryTimes.some((value) => value === null)) {
    throw new Error(`Runtime adapter ${input.toolId} has an invalid attestation time`);
  }
  const observedAt = Math.max(...observedTimes as number[]);
  const expiresAt = Math.min(...expiryTimes as number[]);
  if (expiresAt <= observedAt) {
    throw new Error(`Runtime adapter ${input.toolId} has no overlapping attestation lifetime`);
  }
  return createRuntimeAdapterAttestation({
    toolId: input.toolId,
    ...(input.dependencyId ? { dependencyId: input.dependencyId } : {}),
    ...(input.parentBindingSha256
      ? { parentBindingSha256: input.parentBindingSha256 }
      : {}),
    executionJourneys: input.executionJourneys,
    binding: input.binding,
    observedAt: new Date(observedAt).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
  });
}

/**
 * Joins the reviewed Guided local-tool projection to the additive Autonomous
 * Safe Recon route. Exported so the complete production-shaped manifest join
 * can be regression-tested without starting a worker or contacting a target.
 */
export function composeMultiToolManifests(input: Readonly<{
  database?: SqliteDatabase;
  baseline?: RuntimeSourceManifests;
  manifest: LocalToolCapabilityManifest;
  activationReceipts: readonly LocalToolActivationReceipt[];
  configuration: AutonomousDnsRuntimeConfiguration & { readonly ipRecon: AutonomousIpSafeReconConfiguration };
  providerAttestation: LocalDeterministicProviderAttestation;
  /**
   * Set only by the trusted activation root after the exact configured local
   * catalogue and, when requested, the mission-scoped NVD adapter are mounted.
   */
  cveRuntimeComposition?: AutonomousCveRuntimeComposition;
  exploitCandidateMaterializer?: AutonomousReusableExploitCandidateMaterializerPort;
  exploitOutcomeObserver?: AutonomousExploitOutcomeObserverPort;
  exploitSandboxAttestation?: ExactTargetSandboxAttestation;
  scriptSourceStore?: ScriptSourceStore;
  brainContext?: BrainContextService;
  candidateLinuxTransportReady?: boolean;
  now?: Date;
}>): RuntimeSourceManifests {
  const compositionNow =
    input.now ?? new Date(input.providerAttestation.attestedAt);
  if (!Number.isFinite(compositionNow.getTime())) {
    throw new Error("Runtime composition observation time is invalid");
  }
  if (!input.configuration.exploitValidation && (
    input.exploitCandidateMaterializer
    || input.exploitOutcomeObserver
    || input.exploitSandboxAttestation
    || input.scriptSourceStore
    || input.brainContext
    || input.candidateLinuxTransportReady
  )) {
    throw new Error(
      "Exploit-validation composition inputs require an enabled runtime configuration",
    );
  }
  if (!input.configuration.cveApplicability
    && input.cveRuntimeComposition !== undefined) {
    throw new Error(
      "CVE composition readiness was supplied without an enabled runtime configuration",
    );
  }
  const exploitPathReadiness = inspectExploitPathComposition({
    ...(input.database ? { database: input.database } : {}),
    configuration: input.configuration,
    ...(input.exploitCandidateMaterializer
      ? { candidateMaterializer: input.exploitCandidateMaterializer }
      : {}),
    ...(input.exploitOutcomeObserver
      ? { outcomeObserver: input.exploitOutcomeObserver }
      : {}),
    ...(input.exploitSandboxAttestation
      ? { exploitSandboxAttestation: input.exploitSandboxAttestation }
      : {}),
    ...(input.scriptSourceStore
      ? { scriptSourceStore: input.scriptSourceStore }
      : {}),
    ...(input.brainContext
      ? { brainContext: input.brainContext }
      : {}),
    now: compositionNow,
  });
  const base = input.baseline ?? {
    riskClasses: [], evidenceKinds: [], capabilities: [], tools: [],
    mcpServers: [], agents: [], providers: [],
  };
  buildRuntimeCapabilityProjection(base);
  const local = input.manifest.toRuntimeSourceManifests(
    input.activationReceipts,
    new Date(input.providerAttestation.attestedAt),
  );
  const toolIds = requiredToolIds(input.configuration);
  const fullTcp = input.configuration.fullTcpBaseline;
  const webSurface = input.configuration.webSurface;
  const candidateLinuxTransportReady =
    input.candidateLinuxTransportReady === true;
  const plannerToolIds = [...authorizedPlannerToolIds(
    input.configuration,
    candidateLinuxTransportReady,
  )];
  const actionClassIds = [...new Set([
    AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
    AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
    fullTcp
      ? AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS
      : AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
    ...(webSurface ? [
      AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
      AUTONOMOUS_WHATWEB_ACTION_CLASS,
      ...(autonomousEndpointDiscoveryEnabled(webSurface)
        ? [AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS]
        : []),
    ] : []),
    ...(input.configuration.cveApplicability
      ? [AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS]
      : []),
    ...(input.configuration.vulnerabilityAssessment
      ? [AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS]
      : []),
    ...(input.configuration.exploitValidation
      ? [AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS]
      : []),
    ...(candidateLinuxTransportReady
      ? [...AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES]
      : []),
  ])];
  const evidenceTypeIds = [...new Set([
    AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE,
    AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE,
    fullTcp ? AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE : AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE,
    fullTcp ? AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE : AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
    ...(webSurface ? [
      AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE,
      AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
      ...(autonomousEndpointDiscoveryEnabled(webSurface)
        ? [AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE]
        : []),
    ] : []),
    ...(input.configuration.cveApplicability
      ? [AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE]
      : []),
    ...(input.configuration.vulnerabilityAssessment
      ? [AUTONOMOUS_VULNERABILITY_ASSESSMENT_EVIDENCE_TYPE]
      : []),
    ...(input.configuration.exploitValidation
      ? [...AUTONOMOUS_EXPLOIT_VALIDATION_EVIDENCE_TYPES]
      : []),
    ...(input.configuration.exploitValidation
      ? ["session_command_outcome", "privilege_access_proof"]
      : []),
  ])];
  const sourceTools = toolIds.map((toolId) => {
    const tool = local.tools.find(({ id }) => id === toolId);
    if (!tool?.available) throw new Error(`The current Safe Recon tool is unavailable: ${toolId}`);
    return tool;
  });
  const riskClasses = [...base.riskClasses];
  for (const sourceTool of sourceTools) {
    for (const riskId of sourceTool.riskClassIds) {
      const sourceRisk = local.riskClasses.find(({ id }) => id === riskId);
      const actionIds = sourceTool.actionClassIds;
      const index = riskClasses.findIndex(({ id }) => id === riskId);
      if (index >= 0) {
        const existing = riskClasses[index]!;
        riskClasses[index] = Object.freeze({
          ...existing,
          actionClassIds: Object.freeze([...new Set([...existing.actionClassIds, ...actionIds])]),
        });
      } else if (sourceRisk) {
        riskClasses.push(Object.freeze({ ...sourceRisk, actionClassIds: Object.freeze([...actionIds]) }));
      } else {
        throw new Error(`Safe Recon risk mapping is missing: ${riskId}`);
      }
    }
  }
  const capabilities = [...base.capabilities];
  const tools = [...base.tools];
  for (const sourceTool of sourceTools) {
    const existingTool = tools.find(({ id }) => id === sourceTool.id);
    if (existingTool && (
      existingTool.locallyPolicyEnforced !== true
      || existingTool.requiresModel !== false
      || existingTool.mcpServerId !== sourceTool.mcpServerId
      || !sameStableIds(existingTool.actionClassIds, sourceTool.actionClassIds)
      || !sameStableIds(existingTool.evidenceTypeIds, sourceTool.evidenceTypeIds)
      || !sameStableIds(existingTool.riskClassIds, sourceTool.riskClassIds)
    )) throw new Error(`runtime tool stable ID collision: ${sourceTool.id}`);
    const readyTool = Object.freeze({
      ...(existingTool ?? sourceTool),
      available: true,
      locallyPolicyEnforced: true,
      requiresModel: false,
      executionJourneys: Object.freeze(
        sourceTool.id === AUTONOMOUS_HTTP_METADATA_TOOL_ID
          || sourceTool.id === AUTONOMOUS_WHATWEB_TOOL_ID
          || sourceTool.id === AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID
          ? (["guided"] as const)
          : (["autonomous", "guided"] as const),
      ),
      dependencies: Object.freeze([...(sourceTool.dependencies ?? [])]),
    });
    if (existingTool) tools[tools.indexOf(existingTool)] = readyTool;
    else tools.push(readyTool);

    const capabilityId = `capability:${sourceTool.id}`;
    const sourceCapability = local.capabilities.find(({ id }) => id === capabilityId);
    if (!sourceCapability) throw new Error(`Safe Recon capability is missing: ${capabilityId}`);
    const existingCapability = capabilities.find(({ id }) => id === capabilityId);
    if (existingCapability && (
      !sameStableIds(existingCapability.actionClassIds, sourceCapability.actionClassIds)
      || !sameStableIds(existingCapability.evidenceTypeIds ?? [], sourceCapability.evidenceTypeIds ?? [])
    )) throw new Error(`runtime capability stable ID collision: ${capabilityId}`);
    if (!existingCapability) capabilities.push(sourceCapability);
  }
  if (fullTcp) {
    const phaseTools = sourceTools.filter(({ id }) =>
      id === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
      || id === AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID);
    if (phaseTools.length !== 2) {
      throw new Error("The exact Full-TCP phase tools are not both active");
    }
    const virtualRiskClassIds = Object.freeze([...new Set(phaseTools.flatMap(
      ({ riskClassIds }) => riskClassIds,
    ))]);
    const dependenciesById = new Map(phaseTools.flatMap(({ dependencies = [] }) =>
      dependencies.map((dependency) => [dependency.id, dependency] as const)));
    const virtualTool = Object.freeze({
      id: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
      label: "Reviewed exact-IP full TCP baseline composite",
      available: true,
      locallyPolicyEnforced: true,
      requiresModel: false,
      executionJourneys: Object.freeze(["autonomous"] as const),
      constituentToolIds: Object.freeze([
        AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
        AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
      ]),
      actionClassIds: Object.freeze([AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS]),
      evidenceTypeIds: Object.freeze([
        AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
        AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
      ]),
      riskClassIds: virtualRiskClassIds,
      dependencies: Object.freeze([...dependenciesById.values()]),
    });
    const existingVirtualTool = tools.find(({ id }) => id === virtualTool.id);
    if (existingVirtualTool && (
      existingVirtualTool.available !== true
      || existingVirtualTool.locallyPolicyEnforced !== true
      || existingVirtualTool.requiresModel !== false
      || !sameStableIds(
        existingVirtualTool.constituentToolIds ?? [],
        virtualTool.constituentToolIds,
      )
      || !sameStableIds(existingVirtualTool.actionClassIds, virtualTool.actionClassIds)
      || !sameStableIds(existingVirtualTool.evidenceTypeIds, virtualTool.evidenceTypeIds)
      || !sameStableIds(existingVirtualTool.riskClassIds, virtualTool.riskClassIds)
    )) throw new Error(`runtime tool stable ID collision: ${virtualTool.id}`);
    if (!existingVirtualTool) tools.push(virtualTool);
    const capabilityId = `capability:${AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE}`;
    const virtualCapability = Object.freeze({
      id: capabilityId,
      label: "Autonomous exact-IP full TCP baseline",
      actionClassIds: Object.freeze([AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS]),
      evidenceTypeIds: Object.freeze([
        AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
        AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
      ]),
      deliverableIds: AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
    });
    const existingVirtualCapability = capabilities.find(({ id }) => id === capabilityId);
    if (existingVirtualCapability && (
      !sameStableIds(existingVirtualCapability.actionClassIds, virtualCapability.actionClassIds)
      || !sameStableIds(
        existingVirtualCapability.evidenceTypeIds ?? [],
        virtualCapability.evidenceTypeIds,
      )
    )) throw new Error(`runtime capability stable ID collision: ${capabilityId}`);
    if (!existingVirtualCapability) capabilities.push(virtualCapability);
  }
  if (input.configuration.cveApplicability) {
    if (!fullTcp) {
      throw new Error("CVE applicability cannot be projected without the verified Full-TCP phase");
    }
    const versionSources = sourceTools.filter(({ id }) =>
      id === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
      || id === AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID);
    const riskClassIds = Object.freeze([...new Set(versionSources.flatMap(
      ({ riskClassIds }) => riskClassIds,
    ))]);
    if (riskClassIds.length === 0) {
      throw new Error("CVE applicability has no reviewed local risk-class lineage");
    }
    for (const riskClassId of riskClassIds) {
      const index = riskClasses.findIndex(({ id }) => id === riskClassId);
      if (index < 0) throw new Error(`CVE applicability risk mapping is missing: ${riskClassId}`);
      const current = riskClasses[index]!;
      riskClasses[index] = Object.freeze({
        ...current,
        actionClassIds: Object.freeze([
          ...new Set([
            ...current.actionClassIds,
            AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
          ]),
        ]),
      });
    }
    const cveRuntimeReady = autonomousCveRuntimeCompositionValid(
      input.cveRuntimeComposition,
      input.configuration.cveApplicability,
      compositionNow,
    );
    const cveSourceReceipts = input.activationReceipts
      .filter(({ toolId }) =>
        toolId === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
        || toolId === AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID)
      .sort((left, right) => left.toolId.localeCompare(right.toolId));
    if (cveRuntimeReady && cveSourceReceipts.length !== 2) {
      throw new Error("CVE runtime attestation is missing an exact Full-TCP source receipt");
    }
    const cveRuntimeComposition = cveRuntimeReady
      ? input.cveRuntimeComposition!
      : undefined;
    const cveAttestation = cveRuntimeComposition
      ? runtimeAdapterAttestation({
          toolId: AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
          executionJourneys: Object.freeze(["autonomous"] as const),
          observedAt: Object.freeze([
            input.providerAttestation.attestedAt,
            ...cveSourceReceipts.map(({ observedAt }) => observedAt),
            ...(cveRuntimeComposition.nvd
              ? [cveRuntimeComposition.nvd.observedAt]
              : []),
          ]),
          expiresAt: Object.freeze([
            input.providerAttestation.expiresAt,
            ...cveSourceReceipts.map(({ expiresAt }) => expiresAt),
            ...(cveRuntimeComposition.nvd
              ? [cveRuntimeComposition.nvd.expiresAt]
              : []),
          ]),
          binding: Object.freeze({
            configurationSha256: digestCanonicalJson(
              input.configuration.cveApplicability,
              { maxBytes: 64 * 1_024, maxDepth: 12 },
            ).sha256,
            providerReceiptSha256: input.providerAttestation.receiptSha256,
            localManifestSha256: input.manifest.descriptor.manifestSha256,
            componentReceiptSha256s: Object.freeze([
              cveRuntimeComposition.catalog.receiptSha256,
              ...(cveRuntimeComposition.nvd
                ? [cveRuntimeComposition.nvd.receiptSha256]
                : []),
              ...cveSourceReceipts.map((receipt) => digestCanonicalJson(receipt, {
                maxBytes: 64 * 1_024,
                maxDepth: 12,
              }).sha256),
            ]),
          }),
        })
      : undefined;
    const virtualTool = Object.freeze({
      id: AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
      label: "Verified version to authoritative CVE applicability",
      available: cveRuntimeReady,
      locallyPolicyEnforced: true,
      requiresModel: false,
      executionJourneys: Object.freeze(["autonomous"] as const),
      actionClassIds: Object.freeze([AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS]),
      evidenceTypeIds: Object.freeze([AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE]),
      riskClassIds,
      ...(cveAttestation
        ? { runtimeAdapterAttestation: cveAttestation }
        : {}),
      dependencies: Object.freeze([] as const),
    });
    const existingTool = tools.find(({ id }) => id === virtualTool.id);
    if (existingTool && (
      existingTool.available !== virtualTool.available
      || existingTool.locallyPolicyEnforced !== true
      || existingTool.requiresModel !== false
      || existingTool.constituentToolIds !== undefined
      || !sameStableIds(
        existingTool.executionJourneys ?? [],
        virtualTool.executionJourneys,
      )
      || !sameRuntimeAdapterAttestation(
        existingTool.runtimeAdapterAttestation,
        virtualTool.runtimeAdapterAttestation,
      )
      || !sameRuntimeAdapterDependencies(
        existingTool.dependencies,
        virtualTool.dependencies,
      )
      || !sameStableIds(existingTool.actionClassIds, virtualTool.actionClassIds)
      || !sameStableIds(existingTool.evidenceTypeIds, virtualTool.evidenceTypeIds)
      || !sameStableIds(existingTool.riskClassIds, virtualTool.riskClassIds)
    )) throw new Error(`runtime tool stable ID collision: ${virtualTool.id}`);
    if (!existingTool) tools.push(virtualTool);
    const capabilityId = `capability:${AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE}`;
    const capability = Object.freeze({
      id: capabilityId,
      label: virtualTool.label,
      actionClassIds: virtualTool.actionClassIds,
      evidenceTypeIds: virtualTool.evidenceTypeIds,
      deliverableIds: AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
    });
    const existingCapability = capabilities.find(({ id }) => id === capabilityId);
    if (existingCapability && (
      !sameStableIds(existingCapability.actionClassIds, capability.actionClassIds)
      || !sameStableIds(
        existingCapability.evidenceTypeIds ?? [],
        capability.evidenceTypeIds,
      )
    )) throw new Error(`runtime capability stable ID collision: ${capabilityId}`);
    if (!existingCapability) capabilities.push(capability);
  }
  if (webSurface) {
    const webVirtuals = [
      Object.freeze({
        id: AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
        label: "Reviewed evidence-derived HTTP metadata baseline",
        constituentToolIds: Object.freeze([AUTONOMOUS_HTTP_METADATA_TOOL_ID]),
        actionClassIds: Object.freeze([AUTONOMOUS_HTTP_METADATA_ACTION_CLASS]),
        evidenceTypeIds: Object.freeze([AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE]),
      }),
      Object.freeze({
        id: AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
        label: "Reviewed evidence-derived WhatWeb fingerprint",
        constituentToolIds: Object.freeze([AUTONOMOUS_WHATWEB_TOOL_ID]),
        actionClassIds: Object.freeze([AUTONOMOUS_WHATWEB_ACTION_CLASS]),
        evidenceTypeIds: Object.freeze([AUTONOMOUS_WHATWEB_EVIDENCE_TYPE]),
      }),
      ...(autonomousEndpointDiscoveryEnabled(webSurface) ? [Object.freeze({
        id: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
        label: "Reviewed evidence-derived bounded endpoint discovery",
        constituentToolIds: Object.freeze([AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID]),
        actionClassIds: Object.freeze([AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS]),
        evidenceTypeIds: Object.freeze([AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE]),
      })] : []),
      ...(input.configuration.vulnerabilityAssessment ? [Object.freeze({
        id: AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
        label: "Reviewed evidence-derived bounded vulnerability and configuration assessment",
        constituentToolIds: Object.freeze([AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID]),
        actionClassIds: Object.freeze([AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS]),
        evidenceTypeIds: Object.freeze([
          AUTONOMOUS_VULNERABILITY_ASSESSMENT_EVIDENCE_TYPE,
        ]),
      })] : []),
    ] as const;
    for (const virtual of webVirtuals) {
      const constituent = sourceTools.find(({ id }) => id === virtual.constituentToolIds[0]);
      if (!constituent) throw new Error(`Web composite constituent is unavailable: ${virtual.id}`);
      const dependencies = Object.freeze([...(constituent.dependencies ?? [])]);
      const tool = Object.freeze({
        ...virtual,
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: false,
        executionJourneys: Object.freeze(["autonomous"] as const),
        riskClassIds: Object.freeze([...constituent.riskClassIds]),
        dependencies,
      });
      const existingTool = tools.find(({ id }) => id === tool.id);
      if (existingTool && (
        existingTool.available !== true
        || existingTool.locallyPolicyEnforced !== true
        || existingTool.requiresModel !== false
        || !sameStableIds(existingTool.constituentToolIds ?? [], tool.constituentToolIds)
        || !sameStableIds(existingTool.actionClassIds, tool.actionClassIds)
        || !sameStableIds(existingTool.evidenceTypeIds, tool.evidenceTypeIds)
        || !sameStableIds(existingTool.riskClassIds, tool.riskClassIds)
      )) throw new Error(`runtime tool stable ID collision: ${tool.id}`);
      if (!existingTool) tools.push(tool);
      const capabilityId = `capability:${tool.id}`;
      const capability = Object.freeze({
        id: capabilityId,
        label: tool.label,
        actionClassIds: tool.actionClassIds,
        evidenceTypeIds: tool.evidenceTypeIds,
        deliverableIds: AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
      });
      const existingCapability = capabilities.find(({ id }) => id === capabilityId);
      if (existingCapability && (
        !sameStableIds(existingCapability.actionClassIds, capability.actionClassIds)
        || !sameStableIds(
          existingCapability.evidenceTypeIds ?? [],
          capability.evidenceTypeIds,
        )
      )) throw new Error(`runtime capability stable ID collision: ${capabilityId}`);
      if (!existingCapability) capabilities.push(capability);
    }
  }
  if (input.configuration.exploitValidation) {
    const attestation = input.exploitSandboxAttestation;
    const exploitAttestationTimes = attestation
      ? Object.freeze({
          observedAt: Object.freeze([
            input.providerAttestation.attestedAt,
            attestation.observedAt,
            ...(exploitPathReadiness.candidateMaterializerReceipt
              ? [exploitPathReadiness.candidateMaterializerReceipt.observedAt]
              : []),
            ...(exploitPathReadiness.outcomeObserverReceipt
              ? [exploitPathReadiness.outcomeObserverReceipt.observedAt]
              : []),
            ...(exploitPathReadiness.scriptSourceStoreReceipt
              ? [exploitPathReadiness.scriptSourceStoreReceipt.observedAt]
              : []),
            ...(exploitPathReadiness.brainContextReceipt
              ? [exploitPathReadiness.brainContextReceipt.observedAt]
              : []),
          ]),
          expiresAt: Object.freeze([
            input.providerAttestation.expiresAt,
            attestation.expiresAt,
            ...(exploitPathReadiness.candidateMaterializerReceipt
              ? [exploitPathReadiness.candidateMaterializerReceipt.expiresAt]
              : []),
            ...(exploitPathReadiness.outcomeObserverReceipt
              ? [exploitPathReadiness.outcomeObserverReceipt.expiresAt]
              : []),
            ...(exploitPathReadiness.scriptSourceStoreReceipt
              ? [exploitPathReadiness.scriptSourceStoreReceipt.expiresAt]
              : []),
            ...(exploitPathReadiness.brainContextReceipt
              ? [exploitPathReadiness.brainContextReceipt.expiresAt]
              : []),
          ]),
        })
      : undefined;
    const exploitRuntimeBinding = exploitPathReadiness.ready
      && exploitAttestationTimes
      && attestation
      && exploitPathReadiness.candidateMaterializerReceipt
      && exploitPathReadiness.outcomeObserverReceipt
      && exploitPathReadiness.scriptSourceStoreReceipt
      && exploitPathReadiness.brainContextReceipt
      ? Object.freeze({
          configurationSha256: digestCanonicalJson(
            input.configuration.exploitValidation,
            { maxBytes: 64 * 1_024, maxDepth: 12 },
          ).sha256,
          providerReceiptSha256: input.providerAttestation.receiptSha256,
          localManifestSha256: input.manifest.descriptor.manifestSha256,
          componentReceiptSha256s: Object.freeze([
            attestation.receiptSha256,
            exploitPathReadiness.candidateMaterializerReceipt.receiptSha256,
            exploitPathReadiness.outcomeObserverReceipt.receiptSha256,
            exploitPathReadiness.scriptSourceStoreReceipt.receiptSha256,
            exploitPathReadiness.brainContextReceipt.receiptSha256,
          ]),
        })
      : undefined;
    const exploitRuntimeAttestation = exploitRuntimeBinding
      && exploitAttestationTimes
      ? runtimeAdapterAttestation({
          toolId: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
          executionJourneys: Object.freeze(["autonomous"] as const),
          ...exploitAttestationTimes,
          binding: exploitRuntimeBinding,
        })
      : undefined;
    const dependencyAttestation = (
      dependencyId: string,
      componentReceiptSha256: string | undefined,
    ):
      RuntimeAdapterAttestation | undefined => {
      if (!exploitRuntimeBinding
        || !exploitAttestationTimes
        || !exploitRuntimeAttestation
        || !componentReceiptSha256) return undefined;
      return runtimeAdapterAttestation({
        toolId: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
        dependencyId,
        parentBindingSha256: exploitRuntimeAttestation.bindingSha256,
        executionJourneys: Object.freeze(["autonomous"] as const),
        ...exploitAttestationTimes,
        binding: Object.freeze({
          ...exploitRuntimeBinding,
          componentReceiptSha256s: Object.freeze([
            componentReceiptSha256,
          ]),
        }),
      });
    };
    const materializerAttestation =
      dependencyAttestation(
        "candidate-specific-materializer",
        exploitPathReadiness.candidateMaterializerReceipt?.receiptSha256,
      );
    const observerAttestation =
      dependencyAttestation(
        "independent-target-impact-observer",
        exploitPathReadiness.outcomeObserverReceipt?.receiptSha256,
      );
    const sandboxDependencyAttestation =
      dependencyAttestation(
        "exact-target-sandbox",
        attestation?.receiptSha256,
      );
    const scriptStoreDependencyAttestation =
      dependencyAttestation(
        "immutable-script-source-store",
        exploitPathReadiness.scriptSourceStoreReceipt?.receiptSha256,
      );
    const brainDependencyAttestation =
      dependencyAttestation(
        "active-second-brain-context",
        exploitPathReadiness.brainContextReceipt?.receiptSha256,
      );
    const existingRisk = riskClasses.find(
      ({ id }) => id === AUTONOMOUS_EXPLOIT_VALIDATION_RISK_CLASS_ID,
    );
    if (existingRisk && !sameStableIds(
      existingRisk.actionClassIds,
      [AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS],
    )) {
      throw new Error(
        `runtime risk stable ID collision: ${AUTONOMOUS_EXPLOIT_VALIDATION_RISK_CLASS_ID}`,
      );
    }
    if (!existingRisk) {
      riskClasses.push(Object.freeze({
        id: AUTONOMOUS_EXPLOIT_VALIDATION_RISK_CLASS_ID,
        label: "Attested exact-target exploit validation",
        actionClassIds: Object.freeze([
          AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
        ]),
      }));
    }
    const virtualTool = Object.freeze({
      id: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
      label: "Approved ScriptArtifact exact-target validation",
      available: exploitPathReadiness.ready,
      locallyPolicyEnforced: true,
      requiresModel: false,
      executionJourneys: Object.freeze(["autonomous"] as const),
      actionClassIds: Object.freeze([
        AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
      ]),
      evidenceTypeIds: AUTONOMOUS_EXPLOIT_VALIDATION_EVIDENCE_TYPES,
      riskClassIds: Object.freeze([
        AUTONOMOUS_EXPLOIT_VALIDATION_RISK_CLASS_ID,
      ]),
      ...(exploitRuntimeAttestation
        ? { runtimeAdapterAttestation: exploitRuntimeAttestation }
        : {}),
      dependencies: Object.freeze([
        Object.freeze({
          id: "candidate-specific-materializer",
          ready: exploitPathReadiness.candidateMaterializerReady,
          ...(materializerAttestation
            ? { runtimeAdapterAttestation: materializerAttestation }
            : {}),
        }),
        Object.freeze({
          id: "independent-target-impact-observer",
          ready: exploitPathReadiness.independentOutcomeObserverReady,
          ...(observerAttestation
            ? { runtimeAdapterAttestation: observerAttestation }
            : {}),
        }),
        Object.freeze({
          id: "exact-target-sandbox",
          ready: exploitPathReadiness.exactTargetSandboxReady,
          ...(sandboxDependencyAttestation
            ? { runtimeAdapterAttestation: sandboxDependencyAttestation }
            : {}),
        }),
        Object.freeze({
          id: "immutable-script-source-store",
          ready: exploitPathReadiness.scriptSourceStoreReady,
          ...(scriptStoreDependencyAttestation
            ? { runtimeAdapterAttestation: scriptStoreDependencyAttestation }
            : {}),
        }),
        Object.freeze({
          id: "active-second-brain-context",
          ready: exploitPathReadiness.brainContextReady,
          ...(brainDependencyAttestation
            ? { runtimeAdapterAttestation: brainDependencyAttestation }
            : {}),
        }),
      ]),
    });
    const existingTool = tools.find(({ id }) => id === virtualTool.id);
    if (existingTool && (
      existingTool.available !== virtualTool.available
      || existingTool.locallyPolicyEnforced !== true
      || existingTool.requiresModel !== false
      || !sameStableIds(
        existingTool.executionJourneys ?? [],
        virtualTool.executionJourneys,
      )
      || !sameRuntimeAdapterAttestation(
        existingTool.runtimeAdapterAttestation,
        virtualTool.runtimeAdapterAttestation,
      )
      || !sameRuntimeAdapterDependencies(
        existingTool.dependencies,
        virtualTool.dependencies,
      )
      || !sameStableIds(
        existingTool.actionClassIds,
        virtualTool.actionClassIds,
      )
      || !sameStableIds(
        existingTool.evidenceTypeIds,
        virtualTool.evidenceTypeIds,
      )
      || !sameStableIds(existingTool.riskClassIds, virtualTool.riskClassIds)
    )) {
      throw new Error(`runtime tool stable ID collision: ${virtualTool.id}`);
    }
    if (!existingTool) tools.push(virtualTool);
    const capabilityId =
      `capability:${AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE}`;
    const capability = Object.freeze({
      id: capabilityId,
      label: virtualTool.label,
      actionClassIds: virtualTool.actionClassIds,
      evidenceTypeIds: virtualTool.evidenceTypeIds,
      deliverableIds: AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
    });
    const existingCapability = capabilities.find(
      ({ id }) => id === capabilityId,
    );
    if (existingCapability && (
      !sameStableIds(
        existingCapability.actionClassIds,
        capability.actionClassIds,
      )
      || !sameStableIds(
        existingCapability.evidenceTypeIds ?? [],
        capability.evidenceTypeIds,
      )
    )) {
      throw new Error(`runtime capability stable ID collision: ${capabilityId}`);
    }
    if (!existingCapability) capabilities.push(capability);
    if (attestation && (
      attestation.boundary.docker !== false
      || attestation.boundary.kubernetes !== false
      || attestation.boundary.exactTargetEgress !== true
      || attestation.boundary.shell !== false
      || attestation.boundary.publicProvider !== false
    )) {
      throw new Error(
        "Exact-target sandbox attestation omitted a required production boundary",
      );
    }
  }
  if (input.configuration.exploitValidation) {
    const candidateActionClasses = [
      "command_session_execution",
      "data_access_impact_validation",
      "privilege_escalation",
      "cleanup_restoration",
    ] as const;
    const existingRisk = riskClasses.find(
      ({ id }) => id === AUTONOMOUS_LINUX_POST_EXPLOIT_RISK_CLASS_ID,
    );
    if (existingRisk && !sameStableIds(
      existingRisk.actionClassIds,
      candidateActionClasses,
    )) {
      throw new Error(
        `runtime risk stable ID collision: ${AUTONOMOUS_LINUX_POST_EXPLOIT_RISK_CLASS_ID}`,
      );
    }
    if (!existingRisk) {
      riskClasses.push(Object.freeze({
        id: AUTONOMOUS_LINUX_POST_EXPLOIT_RISK_CLASS_ID,
        label: "Candidate-bound typed Linux continuation",
        actionClassIds: Object.freeze([...candidateActionClasses]),
      }));
    }
    const candidateTools = [
      Object.freeze({
        id: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[0],
        label: "Independent candidate session identity",
        actionClassIds: Object.freeze(["command_session_execution"]),
        evidenceTypeIds: Object.freeze(["session_command_outcome"]),
      }),
      Object.freeze({
        id: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[1],
        label: "Hash-only user access proof",
        actionClassIds: Object.freeze(["data_access_impact_validation"]),
        evidenceTypeIds: Object.freeze(["privilege_access_proof"]),
      }),
      Object.freeze({
        id: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[2],
        label: "Candidate-bound privilege continuation",
        actionClassIds: Object.freeze(["privilege_escalation"]),
        evidenceTypeIds: Object.freeze(["privilege_access_proof"]),
      }),
      Object.freeze({
        id: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[3],
        label: "Hash-only root access proof",
        actionClassIds: Object.freeze(["data_access_impact_validation"]),
        evidenceTypeIds: Object.freeze(["privilege_access_proof"]),
      }),
      Object.freeze({
        id: AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS[4],
        label: "Verified candidate session cleanup",
        actionClassIds: Object.freeze(["cleanup_restoration"]),
        evidenceTypeIds: Object.freeze(["session_command_outcome"]),
      }),
    ] as const;
    for (const candidate of candidateTools) {
      const tool = Object.freeze({
        ...candidate,
        // Keep the typed continuation visible to intake even when it is not
        // executable. This lets a Complete Engagement fail preflight with the
        // exact missing reviewed transport instead of an opaque "unsupported"
        // class, while planner/agent manifests still omit every unavailable
        // action from executable authority.
        available: candidateLinuxTransportReady,
        locallyPolicyEnforced: true,
        requiresModel: false,
        executionJourneys: Object.freeze(["autonomous"] as const),
        riskClassIds: Object.freeze([
          AUTONOMOUS_LINUX_POST_EXPLOIT_RISK_CLASS_ID,
        ]),
        dependencies: Object.freeze([Object.freeze({
          id: "reviewed-candidate-linux-transport",
          ready: candidateLinuxTransportReady,
        })]),
      });
      const existingTool = tools.find(({ id }) => id === tool.id);
      if (existingTool && (
        existingTool.available !== candidateLinuxTransportReady
        || existingTool.locallyPolicyEnforced !== true
        || existingTool.requiresModel !== false
        || existingTool.constituentToolIds !== undefined
        || !sameStableIds(existingTool.actionClassIds, tool.actionClassIds)
        || !sameStableIds(existingTool.evidenceTypeIds, tool.evidenceTypeIds)
        || !sameStableIds(existingTool.riskClassIds, tool.riskClassIds)
      )) {
        throw new Error(`runtime tool stable ID collision: ${tool.id}`);
      }
      if (!existingTool) tools.push(tool);
      const capabilityId = `capability:${tool.id}`;
      const capability = Object.freeze({
        id: capabilityId,
        label: tool.label,
        actionClassIds: tool.actionClassIds,
        evidenceTypeIds: tool.evidenceTypeIds,
        deliverableIds: AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
      });
      const existingCapability = capabilities.find(
        ({ id }) => id === capabilityId,
      );
      if (existingCapability && (
        !sameStableIds(
          existingCapability.actionClassIds,
          capability.actionClassIds,
        )
        || !sameStableIds(
          existingCapability.evidenceTypeIds ?? [],
          capability.evidenceTypeIds,
        )
      )) {
        throw new Error(`runtime capability stable ID collision: ${capabilityId}`);
      }
      if (!existingCapability) capabilities.push(capability);
    }
  }
  const evidenceKinds = [...base.evidenceKinds];
  for (const evidenceTypeId of evidenceTypeIds) {
    evidenceKinds.push(Object.freeze({
      id: `autonomous-evidence:${evidenceTypeId}`,
      label: `Verified Safe Recon ${evidenceTypeId.replaceAll("_", " ")}`,
      evidenceTypeIds: Object.freeze([evidenceTypeId]),
    }));
  }
  const result: RuntimeSourceManifests = Object.freeze({
    riskClasses: Object.freeze(riskClasses),
    evidenceKinds: Object.freeze(evidenceKinds),
    capabilities: Object.freeze(capabilities),
    tools: Object.freeze(tools),
    mcpServers: base.mcpServers,
    agents: appendUnique("runtime agent", base.agents, Object.freeze({
      id: input.configuration.specialist.id,
      label: input.configuration.specialist.label,
      available: true,
      capabilityIds: Object.freeze(plannerToolIds.map((toolId) => `capability:${toolId}`)),
      actionClassIds: Object.freeze([...actionClassIds]),
      toolIds: Object.freeze([...plannerToolIds]),
      deliverableIds: AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
      modelRefs: Object.freeze([{
        providerId: input.configuration.provider.id,
        modelId: input.configuration.provider.modelId,
      }]),
    })),
    providers: appendUnique("runtime provider", base.providers, Object.freeze({
      id: input.configuration.provider.id,
      authenticated: true,
      healthy: true,
      catalogObservedAt: input.providerAttestation.attestedAt,
      models: Object.freeze([{
        id: input.configuration.provider.modelId,
        displayName: input.configuration.provider.label,
        executionBoundary: "local_deterministic_policy" as const,
        toolCalling: false,
        structuredOutput: true,
        enforcement: "enforced_executor" as const,
        compatibleActionClassIds: Object.freeze([...actionClassIds]),
        disclosureClasses: Object.freeze(["local"]),
      }]),
    })),
  });
  buildRuntimeCapabilityProjection(result);
  return result;
}

function composeManifests(input: Readonly<{
  database: SqliteDatabase;
  baseline?: RuntimeSourceManifests;
  manifest: LocalToolCapabilityManifest;
  activationReceipt: LocalToolActivationReceipt;
  activationReceipts?: readonly LocalToolActivationReceipt[];
  configuration: AutonomousDnsRuntimeConfiguration;
  providerAttestation: LocalDeterministicProviderAttestation;
  cveRuntimeComposition?: AutonomousCveRuntimeComposition;
  exploitCandidateMaterializer?: AutonomousReusableExploitCandidateMaterializerPort;
  exploitOutcomeObserver?: AutonomousExploitOutcomeObserverPort;
  exploitSandboxAttestation?: ExactTargetSandboxAttestation;
  scriptSourceStore?: ScriptSourceStore;
  brainContext?: BrainContextService;
  candidateLinuxTransportReady?: boolean;
  now?: Date;
}>): RuntimeSourceManifests {
  if (input.configuration.ipRecon) {
    if (!input.activationReceipts) throw new Error("Safe Recon activation receipts are missing");
    return composeMultiToolManifests({
      database: input.database,
      baseline: input.baseline,
      manifest: input.manifest,
      activationReceipts: input.activationReceipts,
      configuration: input.configuration as AutonomousDnsRuntimeConfiguration & {
        readonly ipRecon: AutonomousIpSafeReconConfiguration;
      },
      providerAttestation: input.providerAttestation,
      ...(input.cveRuntimeComposition
        ? { cveRuntimeComposition: input.cveRuntimeComposition }
        : {}),
      ...(input.exploitCandidateMaterializer
        ? { exploitCandidateMaterializer: input.exploitCandidateMaterializer }
        : {}),
      ...(input.exploitOutcomeObserver
        ? { exploitOutcomeObserver: input.exploitOutcomeObserver }
        : {}),
      ...(input.exploitSandboxAttestation
        ? { exploitSandboxAttestation: input.exploitSandboxAttestation }
        : {}),
      ...(input.scriptSourceStore
        ? { scriptSourceStore: input.scriptSourceStore }
        : {}),
      ...(input.brainContext
        ? { brainContext: input.brainContext }
        : {}),
      ...(input.candidateLinuxTransportReady
        ? { candidateLinuxTransportReady: true }
        : {}),
      ...(input.now ? { now: input.now } : {}),
    });
  }
  if (input.configuration.exploitValidation
    || input.exploitCandidateMaterializer
    || input.exploitOutcomeObserver
    || input.exploitSandboxAttestation
    || input.scriptSourceStore
    || input.brainContext
    || input.candidateLinuxTransportReady) {
    throw new Error(
      "Exploit validation requires the exact-IP Full-TCP multi-tool composition",
    );
  }
  const base = input.baseline ?? {
    riskClasses: [], evidenceKinds: [], capabilities: [], tools: [],
    mcpServers: [], agents: [], providers: [],
  };
  buildRuntimeCapabilityProjection(base);
  const local = input.manifest.toRuntimeSourceManifests(
    [input.activationReceipt],
    new Date(input.providerAttestation.attestedAt),
  );
  const sourceTool = local.tools.find(({ id }) => id === AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID);
  if (!sourceTool?.available) throw new Error("The current DNS tool manifest is unavailable");
  const capabilityId = `capability:${AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID}`;
  const riskId = sourceTool.riskClassIds[0];
  if (!riskId) throw new Error("The DNS tool has no reviewed risk class");
  const risk = base.riskClasses.find(({ id }) => id === riskId);
  const riskClasses = risk
    ? base.riskClasses.map((item) => item.id === riskId
      ? Object.freeze({
          ...item,
          actionClassIds: Object.freeze([...new Set([
            ...item.actionClassIds, AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
          ])]),
        })
      : item)
    : [...base.riskClasses, Object.freeze({
        id: riskId,
        label: "Authorized network interaction",
        actionClassIds: Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS]),
      })];
  const existingTool = base.tools.find(({ id }) => id === sourceTool.id);
  if (existingTool && (existingTool.locallyPolicyEnforced !== true
    || existingTool.requiresModel !== false
    || existingTool.mcpServerId !== sourceTool.mcpServerId
    || !sameStableIds(existingTool.actionClassIds, sourceTool.actionClassIds)
    || !sameStableIds(existingTool.evidenceTypeIds, sourceTool.evidenceTypeIds)
    || !sameStableIds(existingTool.riskClassIds, sourceTool.riskClassIds))) {
    throw new Error(`runtime tool stable ID collision: ${sourceTool.id}`);
  }
  const sourceCapability = local.capabilities.find(({ id }) => id === capabilityId);
  if (!sourceCapability) throw new Error("The DNS tool has no reviewed capability mapping");
  const existingCapability = base.capabilities.find(({ id }) => id === capabilityId);
  if (existingCapability && (
    !sameStableIds(existingCapability.actionClassIds, sourceCapability.actionClassIds)
    || !sameStableIds(
      existingCapability.evidenceTypeIds ?? [],
      sourceCapability.evidenceTypeIds ?? [],
    )
  )) {
    throw new Error(`runtime capability stable ID collision: ${capabilityId}`);
  }
  const tool = Object.freeze({
    ...(existingTool ?? sourceTool),
    available: true,
    locallyPolicyEnforced: true,
    // Planning, execution, and evaluation use the reviewed local direct-argv
    // route. Optional MCP capability inventory is not an execution dependency.
    requiresModel: false,
    executionJourneys: Object.freeze(["autonomous", "guided"] as const),
    // Provider and specialist readiness are composition-level authorities,
    // not executable dependencies. Keeping them here without the same local
    // activation attestation makes the generic tool self-test correctly fail
    // an otherwise ready local binding. The exact seven executable boundary
    // dependencies remain joined to one activation receipt.
    dependencies: Object.freeze([...(sourceTool.dependencies ?? [])]),
  });
  const tools = existingTool
    ? base.tools.map((item) => item.id === tool.id ? tool : item)
    : [...base.tools, tool];
  const result: RuntimeSourceManifests = Object.freeze({
    riskClasses: Object.freeze(riskClasses),
    evidenceKinds: appendUnique("runtime evidence kind", base.evidenceKinds, Object.freeze({
      id: `autonomous-evidence:${AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE}`,
      label: "Verified DNS record",
      evidenceTypeIds: Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE]),
    })),
    // Guided and Autonomous may intentionally share the same reviewed DNS
    // tool capability. Reuse only an exactly equivalent canonical mapping;
    // any semantic drift remains a hard stable-ID collision.
    capabilities: existingCapability
      ? base.capabilities
      : appendUnique("runtime capability", base.capabilities, Object.freeze({
          id: capabilityId,
          label: "Autonomous DNS Safe Recon",
          actionClassIds: Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS]),
          evidenceTypeIds: Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE]),
          deliverableIds: AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
        })),
    tools: Object.freeze(tools),
    // Advisory MCP inventory, if separately configured, remains outside this
    // executable runtime manifest.
    mcpServers: base.mcpServers,
    agents: appendUnique("runtime agent", base.agents, Object.freeze({
      id: input.configuration.specialist.id,
      label: input.configuration.specialist.label,
      available: true,
      capabilityIds: Object.freeze([capabilityId]),
      actionClassIds: Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS]),
      toolIds: Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID]),
      deliverableIds: AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
      modelRefs: Object.freeze([{
        providerId: input.configuration.provider.id,
        modelId: input.configuration.provider.modelId,
      }]),
    })),
    providers: appendUnique("runtime provider", base.providers, Object.freeze({
      id: input.configuration.provider.id,
      authenticated: true,
      healthy: true,
      catalogObservedAt: input.providerAttestation.attestedAt,
      models: Object.freeze([{
        id: input.configuration.provider.modelId,
        displayName: input.configuration.provider.label,
        executionBoundary: "local_deterministic_policy" as const,
        toolCalling: false,
        structuredOutput: true,
        enforcement: "enforced_executor" as const,
        compatibleActionClassIds: Object.freeze([AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS]),
        disclosureClasses: Object.freeze(["local"]),
      }]),
    })),
  });
  buildRuntimeCapabilityProjection(result);
  return result;
}

function specialistProjection(
  configuration: AutonomousDnsRuntimeConfiguration,
  heartbeat: AutonomousDnsSpecialistHeartbeat,
  candidateLinuxTransportReady = false,
): FleetAgentProjection {
  const toolIds = authorizedPlannerToolIds(
    configuration,
    candidateLinuxTransportReady,
  );
  const baseCapabilities = configuration.webSurface ? [{
    toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    actionClassId: AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  }, {
    toolId: AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    actionClassId: AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  }, {
    toolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    actionClassId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  }, {
    toolId: AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
    actionClassId: AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
  }, {
    toolId: AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
    actionClassId: AUTONOMOUS_WHATWEB_ACTION_CLASS,
  }, ...(autonomousEndpointDiscoveryEnabled(configuration.webSurface) ? [{
    toolId: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
    actionClassId: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
  }] : [])] : configuration.fullTcpBaseline ? [{
    toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    actionClassId: AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  }, {
    toolId: AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    actionClassId: AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  }, {
    toolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    actionClassId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  }] : configuration.ipRecon ? [{
    toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    actionClassId: AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  }, {
    toolId: AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    actionClassId: AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  }, {
    toolId: AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
    actionClassId: AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
  }] : [{
    toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    actionClassId: AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  }];
  const capabilities = [
    ...baseCapabilities,
    ...(configuration.cveApplicability ? [{
      toolId: AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
      actionClassId: AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
    }] : []),
    ...(configuration.vulnerabilityAssessment ? [{
      toolId: AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
      actionClassId: AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
    }] : []),
    ...(configuration.exploitValidation ? [{
      toolId: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
      actionClassId: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
    }] : []),
    ...(candidateLinuxTransportReady
      ? AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS.map((toolId, index) => ({
          toolId,
          actionClassId: [
            "command_session_execution",
            "data_access_impact_validation",
            "privilege_escalation",
            "data_access_impact_validation",
            "cleanup_restoration",
          ][index]!,
        }))
      : []),
  ];
  return Object.freeze({
    id: configuration.specialist.id,
    role: configuration.ipRecon
      ? "autonomous-safe-reconnaissance-specialist"
      : "autonomous-dns-reconnaissance-specialist",
    displayName: configuration.specialist.label,
    status: "available" as const,
    providerPolicy: Object.freeze({
      providerId: configuration.provider.id,
      modelId: configuration.provider.modelId,
      providerContact: false,
      deterministicPolicy: true,
    }),
    toolPolicy: Object.freeze({
      allowedTools: Object.freeze([...toolIds]),
      deniedTools: Object.freeze([]),
      approvalRequiredTools: Object.freeze([]),
    }),
    configuration: Object.freeze({
      schemaVersion: "ti-scale.autonomous-specialist-runtime.v1",
      executionMode: "reviewed_local_process",
      adapterId: configuration.fullTcpBaseline
        ? AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID
        : configuration.ipRecon ? AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID
        : AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID,
      toolSelection: "exact_persisted_binding_only",
      resultDelivery: "bound_execution_result_sink",
      shellInterpolation: false,
      publicProviderToolExecution: false,
    }),
    version: configuration.specialist.version,
    lastHeartbeatAt: heartbeat.observedAt,
    capabilities: Object.freeze(capabilities.map(({ toolId, actionClassId }) => ({
      // Canonical execution authorization joins agent_capabilities.capability
      // to the exact reviewed tool ID. Descriptive capability grouping stays
      // in the manifest; it must not rename this dispatch allowlist key.
      name: toolId,
      source: "live-route-attestation",
      enabled: true,
      metadata: Object.freeze({
        actionClassId,
        toolId,
        executionBinding: "reviewed_local_process",
        executionJourneys: Object.freeze(["autonomous"]),
        validUntil: heartbeat.expiresAt,
      }),
    }))),
  });
}

function providerAttestationState(
  receipt: LocalDeterministicProviderAttestation,
  configuration: LoadedTrustedJson<AutonomousDnsRuntimeConfiguration>,
  planner: LocalAutonomousContractPlanner,
  evaluator: LocalVerifiedEvidenceOutcomeEvaluator,
  now: Date,
): "valid" | "invalid" | "stale" {
  const config = configuration.value;
  const issued = validTime(receipt.attestedAt);
  const expires = validTime(receipt.expiresAt);
  const exact = receipt.schemaVersion === LOCAL_DETERMINISTIC_PROVIDER_ATTESTATION_SCHEMA_VERSION
    && receipt.receiptSha256 === receiptDigest(receipt)
    && receipt.providerId === config.provider.id
    && receipt.modelId === config.provider.modelId
    && receipt.modelConfigurationHash === config.provider.modelConfigurationHash
    && receipt.configurationSha256 === configuration.receipt.canonicalSha256
    && receipt.policyHash === planner.localPlanningBoundary.policyHash
    && receipt.plannerContractSha256 === digestCanonicalJson(
      planner.autonomousContract, { maxBytes: 16 * 1_024, maxDepth: 8 },
    ).sha256
    && receipt.evaluatorContractSha256 === digestCanonicalJson(
      evaluator.autonomousContract, { maxBytes: 16 * 1_024, maxDepth: 8 },
    ).sha256
    && receipt.boundary.providerContact === false
    && receipt.boundary.providerCredentials === false
    && receipt.boundary.toolDeclarations === false
    && receipt.boundary.toolDispatch === false
    && receipt.boundary.deterministicPlanning === true
    && receipt.boundary.verifiedEvidenceEvaluation === true
    && receipt.boundary.exactTokenUsage === 0 && receipt.boundary.exactCostUsd === 0
    && issued !== null && expires !== null && expires > issued;
  if (!exact) return "invalid";
  return issued! <= now.getTime() && expires! > now.getTime() ? "valid" : "stale";
}

function specialistHeartbeatState(
  receipt: AutonomousDnsSpecialistHeartbeat,
  configuration: LoadedTrustedJson<AutonomousDnsRuntimeConfiguration>,
  manifest: LocalToolCapabilityManifest,
  activations: readonly LocalToolActivationReceipt[],
  now: Date,
): "valid" | "invalid" | "stale" {
  const tool = manifest.resolve(AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID)!;
  const activation = activations.find(({ toolId }) => toolId === tool.toolId)!;
  const issued = validTime(receipt.observedAt);
  const expires = validTime(receipt.expiresAt);
  const expectedContract = configuration.value.fullTcpBaseline
    ? AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT
    : configuration.value.ipRecon ? AUTONOMOUS_LOCAL_SAFE_RECON_EXECUTION_CONTRACT
    : AUTONOMOUS_DNS_LOCAL_PROCESS_EXECUTION_CONTRACT;
  const expectedTools = requiredToolIds(configuration.value).map((toolId) => {
    const currentTool = manifest.resolve(toolId)!;
    const currentActivation = activations.find((receipt) => receipt.toolId === toolId)!;
    return {
      toolId,
      toolBindingSha256: currentActivation?.bindingSha256,
      executableSha256: currentTool?.executable.expectedSha256,
    };
  });
  const multiToolExact = configuration.value.ipRecon
    ? Array.isArray(receipt.tools)
      && receipt.tools.length === expectedTools.length
      && expectedTools.every((expected) => receipt.tools!.some((actual) =>
        actual.toolId === expected.toolId
        && actual.toolBindingSha256 === expected.toolBindingSha256
        && actual.executableSha256 === expected.executableSha256))
    : receipt.tools === undefined;
  const exact = receipt.schemaVersion === AUTONOMOUS_DNS_SPECIALIST_HEARTBEAT_SCHEMA_VERSION
    && receipt.receiptSha256 === receiptDigest(receipt)
    && receipt.specialistId === configuration.value.specialist.id
    && receipt.workerId === configuration.value.specialist.workerId
    && receipt.configurationSha256 === configuration.receipt.canonicalSha256
    && receipt.manifestSha256 === manifest.descriptor.manifestSha256
    && receipt.toolBindingSha256 === activation.bindingSha256
    && receipt.toolBindingSha256 === tool.bindingSha256
    && receipt.executableSha256 === tool.executable.expectedSha256
    && multiToolExact
    && receipt.adapterContractSha256 === digestCanonicalJson(
      expectedContract, { maxBytes: 16 * 1_024, maxDepth: 8 },
    ).sha256
    && receipt.cancellation === "run_scoped_cooperative" && receipt.resultSinkBound === true
    && issued !== null && expires !== null && expires > issued;
  if (!exact) return "invalid";
  return issued! <= now.getTime() && expires! > now.getTime() ? "valid" : "stale";
}

export function parseExactTargetSandboxAttestationTime(
  value: string,
): number | null {
  return validTime(value);
}

function exactTargetSandboxAttestationCurrent(
  attestation: ExactTargetSandboxAttestation,
  manifest: LoadedTrustedJson<ExactTargetSandboxActivationManifest>,
  now: Date,
): boolean {
  const observedAt = parseExactTargetSandboxAttestationTime(
    attestation.observedAt,
  );
  const expiresAt = parseExactTargetSandboxAttestationTime(
    attestation.expiresAt,
  );
  return attestation.schemaVersion
      === "ti-scale.exact-target-sandbox-attestation.v1"
    && attestation.activationManifestSha256 === manifest.receipt.sourceSha256
    && attestation.brokerExecutableSha256
      === manifest.value.broker.executableSha256
    && attestation.bubblewrapExecutableSha256
      === manifest.value.bubblewrap.executableSha256
    && attestation.interpreter.bindingId
      === manifest.value.interpreter.bindingId
    && attestation.interpreter.executableSha256
      === manifest.value.interpreter.executableSha256
    && attestation.boundary.platform === "linux"
    && attestation.boundary.directArgv === true
    && attestation.boundary.shell === false
    && attestation.boundary.immutableStagedSource === true
    && attestation.boundary.minimalFilesystem === "bubblewrap"
    && attestation.boundary.networkConfinement
      === "systemd_cgroup_ip_address_allow"
    && attestation.boundary.exactTargetEgress === true
    && attestation.boundary.targetPortConfinement === false
    && attestation.boundary.arbitraryEnvironment === false
    && attestation.boundary.credentialTransport === false
    && attestation.boundary.publicProvider === false
    && attestation.boundary.boundedOutput === true
    && attestation.boundary.boundedRuntime === true
    && attestation.boundary.cgroupCancellation === true
    && attestation.boundary.docker === false
    && attestation.boundary.kubernetes === false
    && attestation.probe.cgroupV2 === true
    && attestation.probe.ipAddressDenyAny === true
    && attestation.probe.exactAllowedAddressReached === true
    && attestation.probe.unlistedAddressReachableWithoutFilter === true
    && attestation.probe.unlistedAddressBlocked === true
    && attestation.grantsMissionExecution === false
    && SHA256.test(attestation.receiptSha256)
    && attestation.receiptSha256 === receiptDigest(attestation)
    && observedAt !== null
    && expiresAt !== null
    && observedAt <= now.getTime()
    && expiresAt > now.getTime()
    && expiresAt > observedAt
    && expiresAt - observedAt
      <= MAX_EXACT_TARGET_SANDBOX_ATTESTATION_LIFETIME_MS;
}

function blocked(
  baseline: RuntimeProjectionInput,
  blockers: readonly AutonomousDnsActivationBlocker[],
): AutonomousDnsActivationResult {
  return Object.freeze({
    status: "blocked",
    projection: baseline,
    composition: null,
    blockers: Object.freeze([...blockers].sort((left, right) => left.code.localeCompare(right.code))),
  });
}

export interface ComposeAutonomousDnsActivationOptions {
  readonly database: SqliteDatabase;
  readonly baselineProjection: RuntimeProjectionInput;
  readonly manifest: LocalToolCapabilityManifest;
  readonly localActivation: LocalGuidedToolActivationSnapshot;
  readonly configuration: LoadedTrustedJson<AutonomousDnsRuntimeConfiguration>;
  readonly providerAttestation?: LocalDeterministicProviderAttestation;
  readonly specialistHeartbeat?: AutonomousDnsSpecialistHeartbeat;
  /** Optional advisory inventory receipt. It never gates this local route. */
  readonly mcpAttestation?: McpCapabilityAttestation;
  readonly localProcessTransport: ReviewedLocalProcessInvocationAdapter;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  /**
   * Optional exact anonymous NetExec route. Supplying it makes its complete
   * current receipt/adapter/planner/result-sink join mandatory for this
   * activation generation.
   */
  readonly autonomousWindowsIdentity?: AutonomousWindowsIdentityRuntimeBinding;
  /** Required when the evidence-derived web continuation is configured. */
  readonly brainContext?: BrainContextService;
  /** Required when the local CVE applicability continuation is configured. */
  readonly cveCandidateCatalog?: AuthoritativeCveCandidateCatalogPort;
  /** Required only when the trusted configuration explicitly enables exact top-candidate NVD detail. */
  readonly cveNvdEnrichment?: AttestedAutonomousCveNvdEnrichmentPort;
  /** Canonical ScriptArtifact bytes; mandatory only for exploit validation. */
  readonly scriptSourceStore?: ScriptSourceStore;
  /** Mounted candidate-specific, current-evidence/Vault-backed materializer. */
  readonly exploitCandidateMaterializer?: AutonomousReusableExploitCandidateMaterializerPort;
  /** Mounted candidate-specific independent target-impact observer. */
  readonly exploitOutcomeObserver?: AutonomousExploitOutcomeObserverPort;
  /** Root-owned identities loaded through the deployment-pinned manifest. */
  readonly exploitSandboxManifest?: LoadedTrustedJson<ExactTargetSandboxActivationManifest>;
  /** Fresh live broker/cgroup proof obtained by the lifecycle for this wave. */
  readonly exploitSandboxAttestation?: ExactTargetSandboxAttestation;
  /**
   * Fresh, hash-pinned typed transport for one or more canonical candidate
   * specifications. It exposes no generic command, argv, payload, credential,
   * path, or target override.
   */
  readonly candidateLinuxTransport?: CandidateLinuxTransportBindingRegistry;
  /** A configured transport must fail the activation wave when not current. */
  readonly candidateLinuxTransportRequired?: boolean;
  /**
   * Optional live projection reader used by the planner after activation.
   * Production supplies the lifecycle-owned projection so an expired provider,
   * specialist, or local-tool receipt immediately makes subsequent
   * planning fail closed instead of retaining the activation-time snapshot.
   */
  readonly readRuntimeProjection?: () => RuntimeProjectionInput;
  /**
   * Live runtime clock used after activation by the long-lived planner and
   * execution adapter. `now` below is an immutable observation time for one
   * activation wave; reusing it as the runtime clock makes later, freshly
   * rotated receipts appear future-dated to an already-mounted planner.
   */
  readonly runtimeClock?: () => Date;
  readonly now?: Date;
}

/** Builds an unstarted, fail-closed runtime composition and never mutates the application root. */
export function composeAutonomousDnsActivation(
  input: ComposeAutonomousDnsActivationOptions,
): AutonomousDnsActivationResult {
  const now = input.now ?? new Date();
  const blockers: AutonomousDnsActivationBlocker[] = [];
  if (!Number.isFinite(now.getTime()) || !trustedReceiptValid(input.configuration)) {
    return blocked(input.baselineProjection, [blocker(
      "trusted_configuration_invalid",
      "The Autonomous DNS configuration is not backed by a current trusted-file receipt.",
      "Load the exact operator-reviewed JSON through the trusted configuration loader.",
    )]);
  }
  const config = input.configuration.value;
  const autonomousWindowsIdentityReadiness =
    input.autonomousWindowsIdentity
      ? inspectAutonomousWindowsIdentityComposition(
          input.autonomousWindowsIdentity,
          now,
        )
      : undefined;
  if (
    autonomousWindowsIdentityReadiness
    && autonomousWindowsIdentityReadiness.status !== "ready"
  ) {
    return blocked(input.baselineProjection, [blocker(
      "autonomous_windows_identity_unavailable",
      autonomousWindowsIdentityReadiness.reason,
      autonomousWindowsIdentityReadiness.remediation,
    )]);
  }
  const candidateLinuxTransportReadiness =
    input.candidateLinuxTransport?.readiness();
  const candidateLinuxTransportAttested =
    candidateLinuxTransportReadiness?.status === "ready";
  const candidateLinuxTransportReady =
    input.candidateLinuxTransport?.missionExecutionReady() === true;
  if (
    input.candidateLinuxTransportRequired === true
    && !candidateLinuxTransportAttested
  ) {
    return blocked(input.baselineProjection, [blocker(
      "candidate_linux_transport_unavailable",
      candidateLinuxTransportReadiness?.reason
        ?? "The configured candidate Linux transport did not complete a current hash-pinned broker attestation.",
      "Restore the exact Unix-socket broker, active hash-matched candidate specification, and fresh attestation before launching the full-path contract.",
    )]);
  }
  if ((config.webSurface || config.cveApplicability
    || config.vulnerabilityAssessment || config.exploitValidation)
    && !input.brainContext) {
    return blocked(input.baselineProjection, [blocker(
      "second_brain_unavailable",
      "The Autonomous continuation cannot start without the core Second Brain context service.",
      "Mount the local Brain Context service, then repeat activation before mission work.",
    )]);
  }
  if (config.cveApplicability && !input.cveCandidateCatalog) {
    return blocked(input.baselineProjection, [blocker(
      "cve_catalog_unavailable",
      "The Autonomous CVE continuation has no concrete pinned local candidate catalogue.",
      "Load the exact trusted catalogue snapshot named by the runtime configuration, then repeat activation.",
    )]);
  }
  if (config.cveApplicability?.nvdEnrichment === "top_candidate"
    && !input.cveNvdEnrichment) {
    return blocked(input.baselineProjection, [blocker(
      "cve_nvd_binding_unavailable",
      "The trusted runtime requests exact top-candidate NVD detail, but no mission-scoped reviewed binding is mounted.",
      "Mount the exact opaque-reference NVD binding or set NVD enrichment to disabled in a newly reviewed runtime document.",
    )]);
  }
  if (!config.exploitValidation && (
    input.exploitCandidateMaterializer
    || input.exploitOutcomeObserver
    || input.exploitSandboxManifest
    || input.exploitSandboxAttestation
    || input.candidateLinuxTransport
    || input.candidateLinuxTransportRequired
  )) {
    return blocked(input.baselineProjection, [blocker(
      "trusted_configuration_invalid",
      "Exact-target sandbox authority was supplied without an enabled versioned exploit-validation runtime configuration.",
      "Remove the orphan sandbox inputs or enable the reviewed phase in a newly hash-pinned runtime document.",
    )]);
  }
  const currentExploitSandboxAttestation = config.exploitValidation
    && input.exploitSandboxManifest
    && input.exploitSandboxAttestation
    && exactTargetSandboxAttestationCurrent(
      input.exploitSandboxAttestation,
      input.exploitSandboxManifest,
      now,
    )
    ? input.exploitSandboxAttestation
    : undefined;
  const exploitPathReadiness = inspectExploitPathComposition({
    database: input.database,
    configuration: config,
    ...(input.exploitCandidateMaterializer
      ? { candidateMaterializer: input.exploitCandidateMaterializer }
      : {}),
    ...(input.exploitOutcomeObserver
      ? { outcomeObserver: input.exploitOutcomeObserver }
      : {}),
    ...(currentExploitSandboxAttestation
      ? { exploitSandboxAttestation: currentExploitSandboxAttestation }
      : {}),
    ...(input.scriptSourceStore
      ? { scriptSourceStore: input.scriptSourceStore }
      : {}),
    ...(input.brainContext ? { brainContext: input.brainContext } : {}),
    now,
  });
  let cveRuntimeComposition: AutonomousCveRuntimeComposition | undefined;
  if (config.cveApplicability && input.cveCandidateCatalog) {
    try {
      const catalog = input.cveCandidateCatalog.inspectComposition();
      const nvd = config.cveApplicability.nvdEnrichment === "top_candidate"
        ? input.cveNvdEnrichment?.inspectComposition()
        : undefined;
      const candidate = Object.freeze({
        catalog,
        ...(nvd ? { nvd } : {}),
      });
      if (autonomousCveRuntimeCompositionValid(
        candidate,
        config.cveApplicability,
        now,
      )) {
        cveRuntimeComposition = candidate;
      }
    } catch {
      cveRuntimeComposition = undefined;
    }
    if (!cveRuntimeComposition) {
      blockers.push(blocker(
        config.cveApplicability.nvdEnrichment === "top_candidate"
          ? "cve_nvd_binding_unavailable"
          : "cve_catalog_unavailable",
        config.cveApplicability.nvdEnrichment === "top_candidate"
          ? "The exact mission-scoped public NVD binding does not have a current verifiable composition receipt."
          : "The mounted local CVE catalogue does not match the exact configured ID, snapshot, and result cap.",
        config.cveApplicability.nvdEnrichment === "top_candidate"
          ? "Restore the exact live read-only NVD attestation and mission-scoped adapter, then repeat activation."
          : "Reload the deployment-pinned local catalogue and repeat activation without substituting an object-presence check.",
      ));
    }
  }
  if (config.exploitValidation) {
    if (!exploitPathReadiness.scriptSourceStoreReady) {
      blockers.push(blocker(
        "script_source_store_unavailable",
        "Exploit validation has no current proof for the exact immutable ScriptArtifact source store.",
        "Mount the reviewed content-addressed source store and repeat its target-free composition check.",
      ));
    }
    if (!exploitPathReadiness.brainContextReady) {
      blockers.push(blocker(
        "second_brain_unavailable",
        "Exploit validation cannot prove the exact active local Second Brain and health-verified Obsidian Vault set.",
        "Restore the canonical Brain database and active Vault round-trip health, then repeat activation.",
      ));
    }
    if (!exploitPathReadiness.candidateMaterializerReady) {
      blockers.push(blocker(
        "exploit_materializer_unavailable",
        "The candidate-specific current-evidence/Vault materializer is unavailable or does not match its reviewed contract.",
        "Mount the exact local materializer with current evidence, active Vault, and immutable source validation requirements.",
      ));
    }
    if (!exploitPathReadiness.independentOutcomeObserverReady) {
      blockers.push(blocker(
        "exploit_outcome_observer_unavailable",
        "No candidate-specific independent target-impact observer is ready.",
        "Mount the typed observer that verifies target state through custody-preserved evidence rather than process output.",
      ));
    }
    if (!exploitPathReadiness.exactTargetSandboxReady) {
      blockers.push(blocker(
        "exact_target_sandbox_unavailable",
        "The exact-target sandbox manifest and current broker/cgroup attestation do not form one valid execution boundary.",
        "Restore the deployment-pinned sandbox identities and repeat the live target-free broker attestation.",
      ));
    }
    if (exploitPathReadiness.candidateMaterializerReady
      && exploitPathReadiness.independentOutcomeObserverReady
      && exploitPathReadiness.exactTargetSandboxReady
      && exploitPathReadiness.scriptSourceStoreReady
      && exploitPathReadiness.brainContextReady
      && !exploitPathReadiness.exactComponentJoinReady) {
      blockers.push(blocker(
        "exploit_component_join_invalid",
        "The independently inspected exploit components do not bind the same canonical database, ScriptArtifact store, Brain composition, or component receipts.",
        "Rebuild one activation generation from the exact mounted production instances; do not substitute or replay a sibling component receipt.",
      ));
    }
  }
  let planningProjection = input.baselineProjection;
  let planner: LocalAutonomousContractPlanner;
  let evaluator: LocalVerifiedEvidenceOutcomeEvaluator;
  try {
    validateAutonomousDnsSafeReconConfiguration(config.dns, input.manifest);
    if (config.ipRecon) validateAutonomousIpSafeReconConfiguration(config.ipRecon, input.manifest);
    if (config.fullTcpBaseline) {
      validateAutonomousFullTcpBaselineConfiguration(config.fullTcpBaseline, input.manifest);
    }
    if (config.webSurface) {
      validateAutonomousWebSurfaceConfiguration(config.webSurface, input.manifest);
    }
    if (config.cveApplicability) {
      validateAutonomousCveApplicabilityConfiguration(config.cveApplicability);
    }
    if (config.vulnerabilityAssessment) {
      validateAutonomousVulnerabilityAssessmentConfiguration(
        config.vulnerabilityAssessment,
        input.manifest,
      );
    }
    const planningPolicy = createConfiguredAutonomousPlanningPolicy(
      config,
      input.manifest,
      candidateLinuxTransportReady,
      input.autonomousWindowsIdentity
        ? {
            logicalWorkspace:
              input.autonomousWindowsIdentity.logicalWorkspace,
          }
        : undefined,
    );
    const exploitPlanning = config.exploitValidation
      && exploitPathReadiness.ready
      ? new CanonicalAutonomousExploitValidationPlanningGate({
          database: input.database,
          scripts: new ScriptArtifactService(
            input.database,
            input.scriptSourceStore!,
            input.runtimeClock ?? (() => now),
          ),
          outcomeVerifierReadiness: input.exploitOutcomeObserver!,
        })
      : undefined;
    planner = new LocalAutonomousContractPlanner({
      database: input.database,
      policy: planningPolicy,
      ...(exploitPlanning
        ? { exploitValidationPlanning: exploitPlanning }
        : {}),
      readRuntimeProjection: input.readRuntimeProjection ?? (() => planningProjection),
      now: input.runtimeClock ?? (() => now),
    });
    evaluator = new LocalVerifiedEvidenceOutcomeEvaluator(input.database);
  } catch {
    return blocked(input.baselineProjection, [blocker(
      "scope_policy_mismatch",
      "The reviewed Safe Recon scope, action classes, evidence classes, or specialist policy no longer match the executable manifest.",
      "Re-review the exact local Safe Recon configuration and tool manifest; do not broaden a binding.",
    )]);
  }

  const activations = exactActivationReceipts(input.localActivation, config);
  const activation = activations?.[0];
  if (!activations || !activation || input.localActivation.status !== "ready") {
    blockers.push(blocker(
      "local_dns_tool_unavailable",
      "No complete current activation receipt set exists for every reviewed local Safe Recon tool.",
      "Run the isolated installation, executable, sandbox, workspace, result-sink, and cancellation activation wave.",
    ));
  } else {
    const adapter = input.localActivation.adapterReadiness;
    const adapterReceiptValid = adapter !== null && adapter !== undefined
      && (() => {
        const { receiptSha256, ...unsigned } = adapter;
        return receiptSha256 === digestCanonicalJson(
          unsigned, { maxBytes: 512 * 1_024, maxDepth: 24 },
        ).sha256
          && adapter.grantsMissionExecution === false
          && adapter.boundary.directArgv === true
          && adapter.boundary.shell === false
          && adapter.boundary.workspaceResolver === true
          && adapter.boundary.totalOutputBound === true
          && adapter.boundary.cooperativeCancellation === true
          && adapter.boundary.processGroupCleanup === true
          && adapter.boundary.resultSinkBound === true
          && adapter.boundary.targetContact === false;
      })();
    const drifted = activations.some((receipt) => {
      const tool = input.manifest.resolve(receipt.toolId);
      const adapterTool = adapter?.tools.find(({ toolId }) => toolId === receipt.toolId);
      const probe = input.localActivation.toolBindingReadiness.receipts.find(
        ({ toolId }) => toolId === receipt.toolId,
      );
      return !tool
        || receipt.manifestSha256 !== input.manifest.descriptor.manifestSha256
        || receipt.bindingSha256 !== tool.bindingSha256
        || receipt.executableSha256 !== tool.executable.expectedSha256
        || adapterTool?.expectedExecutableSha256 !== tool.executable.expectedSha256
        || probe?.status !== "ready" || probe.code !== "ready"
        || probe.grantsMissionExecution !== false
        || probe.executableIdentity?.sha256 !== tool.executable.expectedSha256
        || probe.probeBoundary.networkIsolationEnforced !== true
        || probe.probeBoundary.filesystemWriteIsolationEnforced !== true
        || probe.probeBoundary.immutableSnapshotExecutionEnforced !== true;
    });
    if (drifted || !adapterReceiptValid
      || adapter?.adapterId !== config.localProcess.adapterId
      || adapter?.manifestSha256 !== input.manifest.descriptor.manifestSha256) {
      blockers.push(blocker(
        "local_dns_executable_drift",
        "A Safe Recon executable identity or manifest binding differs from its reviewed SHA-256.",
        "Withdraw the executable, restore reviewed bytes, and repeat the isolated readiness wave.",
      ));
    } else if (activations.some((receipt) => {
      const observed = validTime(receipt.observedAt);
      const expires = validTime(receipt.expiresAt);
      return observed === null || expires === null
        || observed > now.getTime() || expires <= now.getTime();
    })) {
      blockers.push(blocker(
        "local_dns_tool_receipt_stale",
        "At least one local Safe Recon activation receipt is no longer current.",
        "Repeat the target-free activation wave before composing a runtime.",
      ));
    } else if (activations.some((receipt) =>
      !receipt.installationReady || !receipt.isolatedProbeReady
      || !receipt.invocationAdapterReady || !receipt.workspaceConfinementReady
      || !receipt.resultSinkReady || !receipt.cancellationReady)) {
      blockers.push(blocker(
        "local_dns_tool_unavailable",
        "A Safe Recon tool did not pass every executable, confinement, result, and cancellation boundary.",
        "Repair the failed activation component and generate a complete new receipt.",
      ));
    }
  }

  if (!input.providerAttestation) {
    blockers.push(blocker(
      "provider_attestation_missing",
      "The local deterministic planner/evaluator provider has no content-free readiness receipt.",
      "Attest the exact trusted policy and mounted planner/evaluator contracts locally.",
    ));
  } else {
    const state = providerAttestationState(
      input.providerAttestation, input.configuration, planner, evaluator, now,
    );
    if (state === "invalid") blockers.push(blocker(
      "provider_attestation_invalid",
      "The local deterministic provider receipt does not match the trusted policy and mounted contracts.",
      "Regenerate a content-free receipt from the exact reviewed planner and evaluator objects.",
    ));
    if (state === "stale") blockers.push(blocker(
      "provider_attestation_stale",
      "The local deterministic provider receipt has expired or is future-dated.",
      "Repeat the bounded local provider attestation.",
    ));
  }

  if (!input.specialistHeartbeat) {
    blockers.push(blocker(
      "specialist_heartbeat_missing",
      "The Autonomous DNS specialist has no current worker heartbeat.",
      "Start the isolated specialist worker and obtain a manifest-bound heartbeat.",
    ));
  } else if (activations) {
    const state = specialistHeartbeatState(
      input.specialistHeartbeat, input.configuration, input.manifest, activations, now,
    );
    if (state === "invalid") blockers.push(blocker(
      "specialist_heartbeat_invalid",
      "The specialist heartbeat is not bound to the exact adapter, executable, and trusted configuration.",
      "Restart the reviewed specialist worker and obtain a new exact heartbeat.",
    ));
    if (state === "stale") blockers.push(blocker(
      "specialist_heartbeat_stale",
      "The Autonomous DNS specialist heartbeat is stale.",
      "Restore the worker heartbeat before activation; never infer liveness from configuration.",
    ));
  }

  if (blockers.length > 0 || !activation || !activations || !input.providerAttestation
    || !input.specialistHeartbeat) {
    return blocked(input.baselineProjection, blockers);
  }

  const baseExecution = config.fullTcpBaseline && config.ipRecon
      ? new AutonomousGeneralSafeReconExecutionFactory({
          manifest: input.manifest,
          dnsConfiguration: config.dns,
          ipConfiguration: config.ipRecon,
          fullTcpConfiguration: config.fullTcpBaseline,
          ...(config.webSurface ? { webSurfaceConfiguration: config.webSurface } : {}),
          ...(config.cveApplicability ? {
            cveApplicabilityConfiguration: config.cveApplicability,
          } : {}),
          ...(config.vulnerabilityAssessment ? {
            vulnerabilityAssessmentConfiguration: config.vulnerabilityAssessment,
          } : {}),
          ...(input.cveCandidateCatalog ? {
            cveCandidateCatalog: input.cveCandidateCatalog,
          } : {}),
          ...(input.cveNvdEnrichment ? {
            cveNvdEnrichment: input.cveNvdEnrichment,
          } : {}),
          ...(input.brainContext ? { brainContext: input.brainContext } : {}),
          adapter: input.localProcessTransport,
          workspaceResolver: input.workspaceResolver,
          now: input.runtimeClock ?? (() => now),
        })
      : config.ipRecon ? new AutonomousLocalSafeReconExecutionFactory({
          manifest: input.manifest,
          dnsConfiguration: config.dns,
          ipConfiguration: config.ipRecon,
          adapter: input.localProcessTransport,
          workspaceResolver: input.workspaceResolver,
          now: input.runtimeClock ?? (() => now),
        })
      : new AutonomousDnsLocalProcessExecutionFactory({
          manifest: input.manifest,
          configuration: config.dns,
          adapter: input.localProcessTransport,
          workspaceResolver: input.workspaceResolver,
          now: input.runtimeClock ?? (() => now),
        });
  const exploitExecution = config.exploitValidation && exploitPathReadiness.ready
    ? new AutonomousExploitValidationExecutionFactory({
        baseFactory: baseExecution,
        activationManifest: input.exploitSandboxManifest!,
        scriptSourceStore: input.scriptSourceStore!,
        brainContext: input.brainContext!,
        logicalWorkspace: config.exploitValidation.logicalWorkspace,
        outcomeVerifier: input.exploitOutcomeObserver!,
        ...(candidateLinuxTransportReady ? {
          postExploitFactory: (runtimeInput) => {
            const nowClock = input.runtimeClock ?? (() => now);
            const session = new AutonomousLinuxPostExploitResultAwarePort({
              database: runtimeInput.database,
              service: new AutonomousLinuxPostExploitSessionService({
                database: runtimeInput.database,
                brainContext: input.brainContext!,
                adapter: new BoundedCandidateRuntimeLinuxSessionAdapter(
                  input.candidateLinuxTransport!,
                ),
                assertControlPlaneAuthority:
                  runtimeInput.assertControlPlaneAuthority,
                agentId: config.exploitValidation!.agentId,
                now: nowClock,
              }),
              now: nowClock,
            });
            const privilege =
              new AutonomousLinuxPrivilegeContinuationResultAwarePort({
                database: runtimeInput.database,
                runtime: new CandidateLinuxPrivilegeContinuationRuntime({
                  database: runtimeInput.database,
                  adapter: new BoundedCandidateRuntimeLinuxPrivilegeAdapter(
                    input.candidateLinuxTransport!,
                  ),
                  brain: new MissionBrainCandidateLinuxPrivilegeContext({
                    database: runtimeInput.database,
                    brainContext: input.brainContext!,
                  }),
                  assertControlPlaneAuthority:
                    runtimeInput.assertControlPlaneAuthority,
                  leaseOwner:
                    `${config.exploitValidation!.agentId}:candidate-linux`,
                  now: nowClock,
                }),
                now: nowClock,
              });
            return new AutonomousLinuxPostExploitCompositePort(
              session,
              privilege,
            );
          },
        } : {}),
        now: input.runtimeClock ?? (() => now),
      })
    : baseExecution;
  const execution = input.autonomousWindowsIdentity
    ? new AutonomousWindowsIdentityExecutionFactory(
        exploitExecution,
        {
          pack: input.autonomousWindowsIdentity.registry.pack,
          adapter: input.autonomousWindowsIdentity.adapter,
          now: input.runtimeClock ?? (() => now),
        },
      )
    : exploitExecution;
  const adapters: ProductionAutonomousRuntimeAdapters = Object.freeze({
    planner,
    outcomeEvaluator: evaluator,
    execution,
  });

  let projection: RuntimeProjectionInput;
  try {
    const manifests = composeManifests({
      database: input.database,
      baseline: input.baselineProjection.capabilityManifests,
      manifest: input.manifest,
      activationReceipt: activation,
      activationReceipts: activations,
      configuration: config,
      providerAttestation: input.providerAttestation,
      ...(cveRuntimeComposition ? { cveRuntimeComposition } : {}),
      ...(input.exploitCandidateMaterializer
        ? { exploitCandidateMaterializer: input.exploitCandidateMaterializer }
        : {}),
      ...(input.exploitOutcomeObserver
        ? { exploitOutcomeObserver: input.exploitOutcomeObserver }
        : {}),
      ...(currentExploitSandboxAttestation
        ? { exploitSandboxAttestation: currentExploitSandboxAttestation }
        : {}),
      ...(input.scriptSourceStore
        ? { scriptSourceStore: input.scriptSourceStore }
        : {}),
      ...(input.brainContext
        ? { brainContext: input.brainContext }
        : {}),
      ...(candidateLinuxTransportReady
        ? { candidateLinuxTransportReady: true }
        : {}),
      now,
    });
    const baseProjection: RuntimeProjectionInput = Object.freeze({
      ...input.baselineProjection,
      readiness: Object.freeze({
        ...input.baselineProjection.readiness,
        // The production baseline is intentionally fail-closed and therefore
        // cannot advertise these invariants before a route exists. Reaching
        // this point proves the exact executable receipt, local deterministic
        // provider attestation, specialist heartbeat, result-sink binding,
        // workspace confinement, and cancellation boundary. Promote the
        // route-owned delegation/no-hands facts for the composition check;
        // any later adapter or manifest mismatch still returns the untouched
        // fail-closed baseline below.
        actionBoundaryActive: true,
        delegationEnforced: true,
        noHandsCommanderEnforced: true,
        directCommanderToolsDenied: true,
        specialistAssignmentRequired: true,
        specialistsConfigured: input.baselineProjection.readiness.specialistsConfigured + 1,
        providers: Object.freeze([...input.baselineProjection.readiness.providers, Object.freeze({
          id: config.provider.id,
          health: "healthy" as const,
          executionBoundary: "local_deterministic_policy" as const,
          configured: true,
          authenticated: true,
          callable: true,
          attestedAt: input.providerAttestation.attestedAt,
          expiresAt: input.providerAttestation.expiresAt,
          circuitState: "closed" as const,
          supportsGuided: false,
          enforcesAutonomousBoundary: true,
          reportsExactTokenUsage: true,
          reportsExactCostUsage: true,
          requestedModel: config.provider.modelId,
          returnedModel: config.provider.modelId,
          modelConfigurationHash: config.provider.modelConfigurationHash,
          completionProbeReceiptId: input.providerAttestation.receiptSha256,
          reason: "A fresh content-free local deterministic policy attestation is active; no public provider was contacted.",
        })]),
      }),
      agents: appendUnique(
        "fleet agent", input.baselineProjection.agents,
        specialistProjection(
          config,
          input.specialistHeartbeat,
          candidateLinuxTransportReady,
        ),
      ),
      mcpServers: input.baselineProjection.mcpServers,
      capabilityManifests: manifests,
    });
    projection = input.autonomousWindowsIdentity
      ? composeAutonomousWindowsIdentityProjection(baseProjection, {
          binding: input.autonomousWindowsIdentity,
          providerId: config.provider.id,
          modelId: config.provider.modelId,
          modelConfigurationHash:
            config.provider.modelConfigurationHash,
          executionAdapterId:
            execution.localProcessContract.adapterId,
          now,
        })
      : baseProjection;
    // The planner was instantiated before the projection could be composed so
    // its contract could be attested. Switch its read-only closure only after
    // every exact manifest and live-readiness object has been built.
    planningProjection = projection;
  } catch (error) {
    const collision = error instanceof Error && error.message.trim()
      ? error.message.trim().replace(/[\u0000-\u001f\u007f]/gu, " ").slice(0, 512)
      : "unknown projection collision";
    return blocked(input.baselineProjection, [blocker(
      "runtime_projection_collision",
      `The Autonomous Safe Recon stable IDs collide with an existing runtime route or manifest: ${collision}`,
      "Assign distinct reviewed stable IDs or reconcile the one canonical route before activation.",
    )]);
  }
  const composition = inspectAutonomousRuntimeComposition({
    projection,
    adapters,
    now,
    specialistHeartbeatMaximumAgeMs: config.specialist.heartbeatTtlMs,
  });
  const requiredActionClasses = Object.freeze([
    ...requiredAutonomousSafeReconActionClassIds(
      config,
      candidateLinuxTransportReady,
    ),
    ...(input.autonomousWindowsIdentity
      ? [AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS]
      : []),
  ]);
  const missingActionClasses = requiredActionClasses.filter(
    (actionClassId) => !composition.readyActionClassIds.includes(actionClassId),
  );
  if (composition.status !== "ready"
    || missingActionClasses.length > 0) {
    return blocked(input.baselineProjection, [blocker(
      "autonomous_composition_blocked",
      composition.blockers[0]?.impact
        ?? `The final Autonomous composition did not expose these exact Safe Recon action classes: ${missingActionClasses.join(", ")}.`,
      composition.blockers[0]?.remediation
        ?? "Reconcile the trusted planner, specialist, provider, and local-tool identities.",
    )]);
  }
  const readyProjection = Object.freeze({
    ...projection,
    readiness: Object.freeze({
      ...projection.readiness,
      autonomousRuntime: composition,
    }),
  });
  // Consumers outside the lifecycle (preflight, intake tests, and any future
  // additive composition root) must see the same exact adapter proof that was
  // used to admit this activation. A ready composition kept only beside the
  // projection made the HTTP readiness path fail closed even though the
  // mounted runtime itself was valid.
  planningProjection = readyProjection;
  return Object.freeze({
    status: "ready",
    projection: readyProjection,
    adapters,
    composition,
    blockers: Object.freeze([] as const),
  });
}

export function autonomousDnsConfigurationReceipt(
  loaded: LoadedTrustedJson<AutonomousDnsRuntimeConfiguration>,
): TrustedLocalFileReceipt {
  if (!trustedReceiptValid(loaded)) throw new Error("Autonomous DNS trusted receipt is invalid");
  return loaded.receipt;
}

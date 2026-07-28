import type { LocalToolCapabilityManifest } from "../local-tools";
import { AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION } from "../domain";
import {
  validateLocalAutonomousPlanningPolicy,
} from "./LocalAutonomousContractPlanner";
import {
  createAutonomousDnsSafeReconPlanningPolicy,
  type AutonomousDnsSafeReconConfiguration,
} from "./AutonomousDnsSafeRecon";
import {
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  createAutonomousIpSafeReconPlanningPolicy,
  type AutonomousIpSafeReconConfiguration,
} from "./AutonomousIpSafeRecon";
import {
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
  AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
  createAutonomousFullTcpBaselinePolicy,
  type AutonomousFullTcpBaselineConfiguration,
} from "./AutonomousFullTcpBaseline";
import type { LocalAutonomousPlanningPolicy } from "./types";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE,
  AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE,
  AUTONOMOUS_WHATWEB_ACTION_CLASS,
  AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  autonomousEndpointDiscoveryEnabled,
  validateAutonomousWebSurfaceConfiguration,
  type AutonomousWebSurfacePlanningConfiguration,
} from "./AutonomousWebSurfaceBaseline";
import {
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE,
  validateAutonomousCveApplicabilityConfiguration,
  type AutonomousCveApplicabilityConfiguration,
} from "./AutonomousCveApplicability";
import {
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_EVIDENCE_TYPE,
  AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_ID,
  AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_SHA256,
  validateAutonomousVulnerabilityAssessmentConfiguration,
  type AutonomousVulnerabilityAssessmentConfiguration,
} from "./AutonomousVulnerabilityAssessment";

export const AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID =
  "ti-scale:autonomous-general-safe-recon" as const;

export const AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT = Object.freeze({
  schemaVersion: "ti-scale.autonomous-local-process-execution.v1" as const,
  adapterId: AUTONOMOUS_GENERAL_SAFE_RECON_ADAPTER_ID,
  executionBinding: "reviewed_local_process" as const,
  directArgv: true as const,
  shell: false as const,
  resultDelivery: "bound_execution_result_sink" as const,
  cancellation: "run_scoped_cooperative" as const,
  publicProviderToolExecution: false as const,
});

export interface AutonomousFullTcpPlanningConfiguration
  extends AutonomousFullTcpBaselineConfiguration {
  /** Exact canonical mission criterion satisfied only by the verified composite result. */
  readonly successCriterion: string;
}

function criterion(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized !== value || normalized.length > 2_000
    || /[\u0000-\u001F\u007F]/u.test(normalized)
    || normalized !== AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION) {
    throw new TypeError(
      "fullTcpBaseline.successCriterion must be the canonical registry-backed port/service criterion",
    );
  }
  return normalized;
}

/**
 * Builds the general local reconnaissance policy. Full-TCP is an alternative
 * implementation of the port/service class, never an additional ambiguous
 * binding for the same host. Its virtual action type is backed by exactly two
 * separately attested process tools at the execution boundary.
 */
export function createAutonomousGeneralSafeReconPlanningPolicy(
  dns: AutonomousDnsSafeReconConfiguration,
  ip: AutonomousIpSafeReconConfiguration,
  fullTcp: AutonomousFullTcpPlanningConfiguration,
  manifest: LocalToolCapabilityManifest,
  webSurface?: AutonomousWebSurfacePlanningConfiguration,
  cveApplicability?: AutonomousCveApplicabilityConfiguration,
  vulnerabilityAssessment?: AutonomousVulnerabilityAssessmentConfiguration,
): LocalAutonomousPlanningPolicy {
  const dnsPolicy = createAutonomousDnsSafeReconPlanningPolicy(dns, manifest);
  const ipPolicy = createAutonomousIpSafeReconPlanningPolicy(ip, manifest);
  const fullTcpPolicy = createAutonomousFullTcpBaselinePolicy(fullTcp, manifest);
  const liveness = ipPolicy.bindings.find((binding) =>
    binding.actionClassId === AUTONOMOUS_IP_LIVENESS_ACTION_CLASS
    && "executionBinding" in binding
    && binding.toolId === AUTONOMOUS_IP_LIVENESS_TOOL_ID);
  if (!liveness) throw new Error("The general Safe Recon policy is missing exact host liveness");
  if (
    dnsPolicy.policyId !== ipPolicy.policyId
    || dnsPolicy.policyId !== fullTcpPolicy.policyId
    || dns.agentId !== ip.agentId || dns.agentId !== fullTcpPolicy.agentId
    || dns.providerId !== ip.providerId || dns.providerId !== fullTcpPolicy.providerId
    || dns.modelId !== ip.modelId || dns.modelId !== fullTcpPolicy.modelId
    || dns.modelConfigurationHash !== ip.modelConfigurationHash
    || dns.modelConfigurationHash !== fullTcpPolicy.modelConfigurationHash
  ) {
    throw new TypeError("DNS, host discovery, and full-TCP bindings must share one reviewed policy identity");
  }
  const web = webSurface
    ? validateAutonomousWebSurfaceConfiguration(webSurface, manifest)
    : undefined;
  if (web && (
    web.policyId !== dnsPolicy.policyId
    || web.agentId !== dns.agentId
    || web.providerId !== dns.providerId
    || web.modelId !== dns.modelId
    || web.modelConfigurationHash !== dns.modelConfigurationHash
    || web.logicalWorkspace !== fullTcpPolicy.logicalWorkspace
  )) {
    throw new TypeError("The web-surface continuation must share the exact reviewed Safe Recon policy and workspace identity");
  }
  const cve = cveApplicability
    ? validateAutonomousCveApplicabilityConfiguration(cveApplicability)
    : undefined;
  if (cve && (
    cve.policyId !== dnsPolicy.policyId
    || cve.agentId !== dns.agentId
    || cve.providerId !== dns.providerId
    || cve.modelId !== dns.modelId
    || cve.modelConfigurationHash !== dns.modelConfigurationHash
  )) {
    throw new TypeError("CVE applicability must share the exact reviewed Safe Recon policy and specialist/model identity");
  }
  const vulnerability = vulnerabilityAssessment
    ? validateAutonomousVulnerabilityAssessmentConfiguration(
        vulnerabilityAssessment,
        manifest,
      )
    : undefined;
  if (vulnerability && (!web || (
    vulnerability.policyId !== dnsPolicy.policyId
    || vulnerability.agentId !== dns.agentId
    || vulnerability.providerId !== dns.providerId
    || vulnerability.modelId !== dns.modelId
    || vulnerability.modelConfigurationHash !== dns.modelConfigurationHash
    || vulnerability.logicalWorkspace !== fullTcpPolicy.logicalWorkspace
  ))) {
    throw new TypeError(
      "The bounded vulnerability assessment requires the verified web continuation and must share its exact Safe Recon policy, workspace, specialist, and model identity",
    );
  }
  return validateLocalAutonomousPlanningPolicy({
    schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
    policyId: dnsPolicy.policyId,
    maximumSteps: (web ? (autonomousEndpointDiscoveryEnabled(web) ? 6 : 5) : 3)
      + (cve ? 1 : 0) + (vulnerability ? 1 : 0),
    bindings: Object.freeze([
      ...dnsPolicy.bindings,
      liveness,
      Object.freeze({
        bindingId: fullTcpPolicy.bindingId,
        actionClassId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
        // Hostnames can be rebound between authorization and the two process
        // phases. The composite therefore accepts only canonical IP literals.
        targetKinds: Object.freeze(["ip"] as const),
        phase: "full_tcp_baseline",
        title: "Create the reviewed full TCP service baseline",
        objective: "Discover every listening TCP port, then identify services only on that exact discovered set.",
        explanation: "One composite action performs capability-free TCP-connect discovery across 1-65535 and deterministic discovered-port-only light versioning.",
        rationale: "The composite binding preserves one exact authorized host, complete port coverage, bounded rate/output/time, and deterministic phase handoff.",
        successCriteria: Object.freeze([criterion(fullTcp.successCriterion)]),
        reversibility: "The action is read-only network interaction and writes only confined immutable-hash artifacts, verified evidence, and evidence-backed topology.",
        riskClass: "medium" as const,
        idempotent: true,
        destructive: false,
        agentId: fullTcpPolicy.agentId,
        providerId: fullTcpPolicy.providerId,
        modelId: fullTcpPolicy.modelId,
        modelConfigurationHash: fullTcpPolicy.modelConfigurationHash,
        executionBinding: "reviewed_local_process" as const,
        toolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
        targetParameter: "target",
        staticParameters: Object.freeze({ workspace: fullTcpPolicy.logicalWorkspace }),
        capabilityIds: Object.freeze([`capability:${AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE}`]),
        requiredEvidenceTypeIds: Object.freeze([
          AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
          AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
        ]),
      }),
      ...(web ? [
        Object.freeze({
          bindingId: web.httpMetadataBindingId,
          actionClassId: AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
          targetKinds: Object.freeze(["ip"] as const),
          phase: "verified_http_metadata",
          title: "Check the verified web services",
          objective: "Ask each web service discovered in the verified TCP baseline for a small, read-only metadata response.",
          explanation: "Ti-Scale converts only confirmed HTTP service ports into exact HTTP or HTTPS origins, sends one HEAD request without following redirects, and records the response status and safe header metadata.",
          rationale: "This confirms which discovered web services actually respond before deeper fingerprinting, without guessing ports, paths, hostnames, or scope.",
          successCriteria: Object.freeze([web.httpMetadataSuccessCriterion]),
          reversibility: "The action is read-only, follows no redirects, sends no credentials, and retains only redacted response metadata and hashes.",
          riskClass: "medium" as const,
          idempotent: true,
          destructive: false,
          agentId: web.agentId,
          providerId: web.providerId,
          modelId: web.modelId,
          modelConfigurationHash: web.modelConfigurationHash,
          executionBinding: "reviewed_local_process" as const,
          toolId: AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
          targetParameter: "target",
          staticParameters: Object.freeze({ workspace: web.logicalWorkspace }),
          capabilityIds: Object.freeze([`capability:${AUTONOMOUS_HTTP_METADATA_ACTION_TYPE}`]),
          requiredEvidenceTypeIds: Object.freeze([AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE]),
        }),
        Object.freeze({
          bindingId: web.whatwebBindingId,
          actionClassId: AUTONOMOUS_WHATWEB_ACTION_CLASS,
          targetKinds: Object.freeze(["ip"] as const),
          phase: "verified_web_fingerprint",
          title: "Identify the responding web technologies",
          objective: "Run one bounded fingerprint check against each derived origin that returned verified HTTP metadata.",
          explanation: "Ti-Scale checks a small reviewed set of server, page-title, framework-header, and HTML signals. A completed check may truthfully report that no positive technology signal was found.",
          rationale: "Fingerprinting only origins already confirmed by the prior phase prevents blind target expansion and creates reusable, evidence-backed technology context.",
          successCriteria: Object.freeze([web.whatwebSuccessCriterion]),
          reversibility: "The action is read-only, uses one request per confirmed origin, follows no redirects, stores no cookies, and does not test vulnerabilities.",
          riskClass: "medium" as const,
          idempotent: true,
          destructive: false,
          agentId: web.agentId,
          providerId: web.providerId,
          modelId: web.modelId,
          modelConfigurationHash: web.modelConfigurationHash,
          executionBinding: "reviewed_local_process" as const,
          toolId: AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
          targetParameter: "target",
          staticParameters: Object.freeze({ workspace: web.logicalWorkspace }),
          capabilityIds: Object.freeze([`capability:${AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE}`]),
          requiredEvidenceTypeIds: Object.freeze([AUTONOMOUS_WHATWEB_EVIDENCE_TYPE]),
        }),
        ...(autonomousEndpointDiscoveryEnabled(web) ? [Object.freeze({
          bindingId: web.endpointDiscoveryBindingId,
          actionClassId: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
          targetKinds: Object.freeze(["ip"] as const),
          phase: "verified_endpoint_discovery",
          title: "Check a fixed set of common web paths",
          objective: "Check the reviewed 14-path dictionary against each verified responding web origin and retain only attributable results.",
          explanation: "Ti-Scale checks fourteen fixed, operator-reviewed paths with two workers and a ten-request-per-second ceiling. It does not recurse, follow redirects, accept a custom wordlist, or expand beyond the evidence-derived origins.",
          rationale: "The bounded endpoint phase follows verified service and technology evidence, providing a small reusable application-surface map without broad or open-ended fuzzing.",
          successCriteria: Object.freeze([web.endpointDiscoverySuccessCriterion]),
          reversibility: "The action is read-only network interaction, follows no redirects, sends no credentials, and retains raw output only in the Engagement Log.",
          riskClass: "high" as const,
          idempotent: true,
          destructive: false,
          agentId: web.agentId,
          providerId: web.providerId,
          modelId: web.modelId,
          modelConfigurationHash: web.modelConfigurationHash,
          executionBinding: "reviewed_local_process" as const,
          toolId: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
          targetParameter: "target",
          staticParameters: Object.freeze({ workspace: web.logicalWorkspace }),
          capabilityIds: Object.freeze([`capability:${AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE}`]),
          requiredEvidenceTypeIds: Object.freeze([AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE]),
        })] : []),
      ] : []),
      ...(cve ? [Object.freeze({
        bindingId: cve.bindingId,
        actionClassId: AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
        targetKinds: Object.freeze(["ip"] as const),
        phase: "verified_cve_applicability",
        title: "Compare verified product versions with authoritative CVE ranges",
        objective: "Create conservative CVE applicability records only from verified service/product/version evidence and exact authoritative source records.",
        explanation: "Ti-Scale compares the verified product and version with structured affected-version ranges from the pinned local catalogue. A banner-derived match remains possible, never confirmed, until stronger evidence exists.",
        rationale: "Running after service fingerprinting turns version observations into attributable, evidence-linked leads without treating raw command output or a banner as proof of vulnerability.",
        successCriteria: Object.freeze([cve.successCriterion]),
        reversibility: "The action is local and read-only. Optional NVD enrichment can fetch only the exact persisted top candidate through an opaque reviewed reference and never contacts the mission target.",
        riskClass: "low" as const,
        idempotent: true,
        destructive: false,
        agentId: cve.agentId,
        providerId: cve.providerId,
        modelId: cve.modelId,
        modelConfigurationHash: cve.modelConfigurationHash,
        executionBinding: "reviewed_local_process" as const,
        toolId: AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
        targetParameter: "target",
        staticParameters: Object.freeze({
          catalogId: cve.catalogId,
          catalogSnapshotSha256: cve.catalogSnapshotSha256,
        }),
        capabilityIds: Object.freeze([`capability:${AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE}`]),
        requiredEvidenceTypeIds: Object.freeze([AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE]),
      })] : []),
      ...(vulnerability ? [Object.freeze({
        bindingId: vulnerability.bindingId,
        actionClassId: AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
        targetKinds: Object.freeze(["ip"] as const),
        phase: "bounded_vulnerability_configuration_assessment",
        title: "Check responding web services for a small reviewed weakness set",
        objective: "Run three fixed read-only HTTP checks against only the responding origins proven by current-run evidence.",
        explanation: "Ti-Scale checks missing security headers, allowed OPTIONS methods, and TRACE exposure. It uses at most four requests per origin, one worker, two requests per second, no redirects, no external callbacks, and no unsigned templates.",
        rationale: "This adds a bounded configuration and vulnerability signal after verified service discovery without guessing hosts, paths, ports, or treating scanner text as a confirmed finding.",
        successCriteria: Object.freeze([vulnerability.successCriterion]),
        reversibility: "The checks are read-only HTTP requests. Raw output stays in the Engagement Log; normalized matches remain reviewable evidence candidates until independently verified.",
        riskClass: "medium" as const,
        idempotent: true,
        destructive: false,
        agentId: vulnerability.agentId,
        providerId: vulnerability.providerId,
        modelId: vulnerability.modelId,
        modelConfigurationHash: vulnerability.modelConfigurationHash,
        executionBinding: "reviewed_local_process" as const,
        toolId: AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
        targetParameter: "target",
        staticParameters: Object.freeze({
          workspace: vulnerability.logicalWorkspace,
          templatePackId: AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_ID,
          templatePackSha256: AUTONOMOUS_VULNERABILITY_TEMPLATE_PACK_SHA256,
        }),
        capabilityIds: Object.freeze([
          `capability:${AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE}`,
        ]),
        requiredEvidenceTypeIds: Object.freeze([
          AUTONOMOUS_VULNERABILITY_ASSESSMENT_EVIDENCE_TYPE,
        ]),
      })] : []),
    ]),
  });
}

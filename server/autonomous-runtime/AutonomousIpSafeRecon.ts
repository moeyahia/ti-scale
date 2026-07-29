import { isIP } from "node:net";
import type { LocalToolCapabilityManifest } from "../local-tools";
import {
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
} from "../domain";
import { validateLocalAutonomousPlanningPolicy } from "./LocalAutonomousContractPlanner";
import {
  createAutonomousDnsSafeReconPlanningPolicy,
  type AutonomousDnsSafeReconConfiguration,
} from "./AutonomousDnsSafeRecon";
import type { LocalAutonomousPlanningPolicy } from "./types";

export const AUTONOMOUS_IP_LIVENESS_TOOL_ID = "kali:ping-host-liveness" as const;
export const AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID =
  "kali:nmap-tcp-connect-service-scan" as const;
export const AUTONOMOUS_IP_LIVENESS_ACTION_CLASS = "active_host_discovery" as const;
export const AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS =
  "port_service_enumeration" as const;
export const AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE = "asset_discovery_proof" as const;
export const AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE =
  "port_service_scan_result" as const;
export const AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE =
  "service_version_fingerprint" as const;
export const AUTONOMOUS_IP_SAFE_RECON_ADAPTER_ID =
  "ti-scale:autonomous-ip-safe-recon" as const;

/**
 * Small, operator-reviewable default. The first Autonomous IP route is not a
 * full-range scanner and cannot silently widen this set at runtime.
 */
export const AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS = Object.freeze([
  22, 53, 80, 88, 135, 139, 389, 443, 445, 636, 3389, 5985, 8080, 8443,
] as const);

export const MAX_AUTONOMOUS_SAFE_IP_RECON_PORTS = 64 as const;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const HOST_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u;
const SECRET = /(?:api[-_]?key|authorization|bearer|cookie|credential|password|private[-_]?key|secret|session[-_]?token)/iu;

export interface AutonomousIpSafeReconConfiguration {
  readonly policyId: string;
  readonly livenessBindingId: string;
  readonly serviceScanBindingId: string;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly logicalWorkspace: string;
  readonly ports: readonly number[];
  readonly livenessSuccessCriterion: string;
  readonly serviceScanSuccessCriterion: string;
}

function safeId(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized !== value || !PUBLIC_ID.test(normalized)) {
    throw new TypeError(`${label} must be a stable public ID`);
  }
  return normalized;
}

function safeText(value: string, label: string, maximum: number): string {
  const normalized = value.trim().normalize("NFKC");
  if (!normalized || normalized !== value || normalized.length > maximum
    || /[\u0000-\u001F\u007F]/u.test(normalized) || SECRET.test(normalized)) {
    throw new TypeError(`${label} must be safe, non-secret text`);
  }
  return normalized;
}

export function normalizeAutonomousIpHost(value: string): string {
  const normalized = value.trim().normalize("NFKC");
  if (!normalized || normalized !== value || normalized.length > 253
    || /[\u0000-\u0020\u007F]/u.test(normalized)) {
    throw new TypeError("Autonomous IP target must be one exact IP address or hostname");
  }
  if (isIP(normalized) !== 0) return normalized.toLocaleLowerCase("en-US");
  const host = normalized.endsWith(".") ? normalized.slice(0, -1) : normalized;
  if (!host || host.split(".").some((label) => !HOST_LABEL.test(label))) {
    throw new TypeError("Autonomous IP target must be one exact IP address or hostname");
  }
  return host.toLocaleLowerCase("en-US");
}

export function normalizeAutonomousSafePorts(value: readonly number[]): readonly number[] {
  if (!Array.isArray(value) || value.length < 1
    || value.length > MAX_AUTONOMOUS_SAFE_IP_RECON_PORTS) {
    throw new RangeError(
      `Autonomous IP ports must contain 1 through ${MAX_AUTONOMOUS_SAFE_IP_RECON_PORTS} reviewed ports`,
    );
  }
  const normalized = [...value].map((port) => {
    if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
      throw new TypeError("Autonomous IP ports must be integers from 1 through 65535");
    }
    return port;
  }).sort((left, right) => left - right);
  if (new Set(normalized).size !== normalized.length) {
    throw new TypeError("Autonomous IP ports must not contain duplicates");
  }
  return Object.freeze(normalized);
}

function exactParameterNames(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
  expected: readonly string[],
): boolean {
  const tool = manifest.resolve(toolId);
  return tool?.parameters.map(({ name }) => name).sort().join("\u0000")
    === [...expected].sort().join("\u0000");
}

export function validateAutonomousIpSafeReconConfiguration(
  input: AutonomousIpSafeReconConfiguration,
  manifest: LocalToolCapabilityManifest,
): AutonomousIpSafeReconConfiguration {
  const ping = manifest.resolve(AUTONOMOUS_IP_LIVENESS_TOOL_ID);
  const nmap = manifest.resolve(AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID);
  if (
    !ping || ping.activation !== "enabled"
    || !ping.actionClassIds.includes(AUTONOMOUS_IP_LIVENESS_ACTION_CLASS)
    || !ping.evidenceTypeIds.includes(AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE)
    || ping.routing.intent !== "host_liveness"
    || ping.routing.targetKind !== "ip_or_host"
    || ping.execution.transport !== "direct_spawn_argv"
    || ping.execution.shell !== false
    || ping.execution.noNewPrivilegesRequired !== true
    || ping.execution.logicalWorkspaceParameter !== "workspace"
    || !exactParameterNames(manifest, AUTONOMOUS_IP_LIVENESS_TOOL_ID, ["target", "workspace"])
  ) {
    throw new Error("The reviewed local manifest does not expose the exact Autonomous IP liveness boundary");
  }
  if (
    !nmap || nmap.activation !== "enabled"
    || !nmap.actionClassIds.includes(AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS)
    || !nmap.evidenceTypeIds.includes(AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE)
    || !nmap.evidenceTypeIds.includes(AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE)
    || nmap.routing.intent !== "port_scan"
    || nmap.routing.targetKind !== "ip_or_host"
    || nmap.execution.transport !== "direct_spawn_argv"
    || nmap.execution.shell !== false
    || nmap.execution.noNewPrivilegesRequired !== true
    || nmap.execution.logicalWorkspaceParameter !== "workspace"
    || !exactParameterNames(
      manifest,
      AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
      ["ports", "target", "workspace"],
    )
  ) {
    throw new Error("The reviewed local manifest does not expose the exact Autonomous IP service-scan boundary");
  }
  if (!SHA256.test(input.modelConfigurationHash)) {
    throw new TypeError("Autonomous IP model configuration hash must be SHA-256");
  }
  if (
    input.livenessSuccessCriterion !== AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION
    || input.serviceScanSuccessCriterion !== AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION
  ) {
    throw new TypeError("Autonomous IP must use the canonical evidence-backed success criteria");
  }
  const livenessBindingId = safeId(input.livenessBindingId, "livenessBindingId");
  const serviceScanBindingId = safeId(input.serviceScanBindingId, "serviceScanBindingId");
  if (livenessBindingId === serviceScanBindingId) {
    throw new TypeError("Autonomous IP binding IDs must be distinct");
  }
  return Object.freeze({
    policyId: safeId(input.policyId, "policyId"),
    livenessBindingId,
    serviceScanBindingId,
    agentId: safeId(input.agentId, "agentId"),
    providerId: safeId(input.providerId, "providerId"),
    modelId: safeId(input.modelId, "modelId"),
    modelConfigurationHash: input.modelConfigurationHash,
    logicalWorkspace: safeText(input.logicalWorkspace, "logicalWorkspace", 4_096),
    ports: normalizeAutonomousSafePorts(input.ports),
    livenessSuccessCriterion: safeText(
      input.livenessSuccessCriterion,
      "livenessSuccessCriterion",
      2_000,
    ),
    serviceScanSuccessCriterion: safeText(
      input.serviceScanSuccessCriterion,
      "serviceScanSuccessCriterion",
      2_000,
    ),
  });
}

export function createAutonomousIpSafeReconPlanningPolicy(
  input: AutonomousIpSafeReconConfiguration,
  manifest: LocalToolCapabilityManifest,
): LocalAutonomousPlanningPolicy {
  const configuration = validateAutonomousIpSafeReconConfiguration(input, manifest);
  const ports = configuration.ports.join(",");
  return validateLocalAutonomousPlanningPolicy({
    schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
    policyId: configuration.policyId,
    maximumSteps: 2,
    bindings: [{
      bindingId: configuration.livenessBindingId,
      actionClassId: AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
      targetKinds: ["ip", "domain"],
      phase: "Reachability baseline",
      title: "Check whether the approved host answers a bounded liveness probe",
      objective: "Record whether the exact approved host replied to two bounded ICMP probes; no reply is retained only as an inconclusive negative fact.",
      explanation: "Ti-Scale sends two short network liveness probes to the one approved host. A reply confirms current reachability. No reply does not prove the host is offline because networks may filter these probes.",
      rationale: "This small first step records reachability without authentication, payload delivery, raw sockets, or target modification.",
      successCriteria: [configuration.livenessSuccessCriterion],
      reversibility: "The action is read-only and creates only a local log, a parsed observation, and deterministically verified evidence.",
      riskClass: "medium",
      idempotent: true,
      destructive: false,
      agentId: configuration.agentId,
      providerId: configuration.providerId,
      modelId: configuration.modelId,
      modelConfigurationHash: configuration.modelConfigurationHash,
      executionBinding: "reviewed_local_process",
      toolId: AUTONOMOUS_IP_LIVENESS_TOOL_ID,
      targetParameter: "target",
      staticParameters: { workspace: configuration.logicalWorkspace },
      capabilityIds: [`capability:${AUTONOMOUS_IP_LIVENESS_TOOL_ID}`],
      requiredEvidenceTypeIds: [AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE],
    }, {
      bindingId: configuration.serviceScanBindingId,
      actionClassId: AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
      targetKinds: ["ip", "domain"],
      phase: "Bounded service baseline",
      title: `Check ${configuration.ports.length} reviewed TCP ports and identify responding services`,
      objective: "Record which ports in the exact reviewed set accepted a TCP connection and retain only service/version text parsed from a complete attributable scan.",
      explanation: `Ti-Scale checks only this reviewed port set: ${ports}. It uses ordinary TCP connections, performs light service identification, runs no scripts, requests no operating-system scan, and does not scan the full port range.`,
      rationale: "A small, explicit service baseline identifies common exposed services while keeping time, traffic, and evidence bounds predictable.",
      successCriteria: [configuration.serviceScanSuccessCriterion],
      reversibility: "The scan is read-only network interaction. It creates local logs and deterministic evidence; it does not authenticate or modify the host.",
      riskClass: "medium",
      idempotent: true,
      destructive: false,
      agentId: configuration.agentId,
      providerId: configuration.providerId,
      modelId: configuration.modelId,
      modelConfigurationHash: configuration.modelConfigurationHash,
      executionBinding: "reviewed_local_process",
      toolId: AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
      targetParameter: "target",
      staticParameters: { workspace: configuration.logicalWorkspace, ports },
      capabilityIds: [`capability:${AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID}`],
      requiredEvidenceTypeIds: [
        AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE,
        AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
      ],
    }],
  });
}

/** Backward-compatible union used by the one production Autonomous runtime. */
export function createAutonomousLocalSafeReconPlanningPolicy(
  dns: AutonomousDnsSafeReconConfiguration,
  ip: AutonomousIpSafeReconConfiguration,
  manifest: LocalToolCapabilityManifest,
): LocalAutonomousPlanningPolicy {
  const dnsPolicy = createAutonomousDnsSafeReconPlanningPolicy(dns, manifest);
  const ipPolicy = createAutonomousIpSafeReconPlanningPolicy(ip, manifest);
  if (dnsPolicy.policyId !== ipPolicy.policyId) {
    throw new TypeError("DNS and IP Safe Recon bindings must share one reviewed policy ID");
  }
  return validateLocalAutonomousPlanningPolicy({
    schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
    policyId: dnsPolicy.policyId,
    maximumSteps: dnsPolicy.maximumSteps + ipPolicy.maximumSteps,
    bindings: Object.freeze([...dnsPolicy.bindings, ...ipPolicy.bindings]),
  });
}

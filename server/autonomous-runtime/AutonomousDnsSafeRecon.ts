import type { LocalToolCapabilityManifest } from "../local-tools";
import { AUTONOMOUS_DNS_A_SUCCESS_CRITERION } from "../domain";
import {
  validateLocalAutonomousPlanningPolicy,
} from "./LocalAutonomousContractPlanner";
import type { LocalAutonomousPlanningPolicy } from "./types";

export const AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID = "kali:host-dns-query" as const;
export const AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS =
  "dns_domain_certificate_discovery" as const;
export const AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE =
  "dns_certificate_record" as const;
export const AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID =
  "ti-scale:autonomous-dns-safe-recon" as const;

export const AUTONOMOUS_DNS_RECORD_TYPES = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "NS",
  "SOA",
  "TXT",
] as const;

export type AutonomousDnsRecordType = (typeof AUTONOMOUS_DNS_RECORD_TYPES)[number];

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SECRET = /(?:api[-_]?key|authorization|bearer|cookie|credential|password|private[-_]?key|secret|session[-_]?token)/iu;

export interface AutonomousDnsSafeReconConfiguration {
  readonly policyId: string;
  readonly bindingId: string;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  /** Compatibility-only advisory inventory identity; local execution never requires it. */
  readonly mcpServerId?: string;
  readonly logicalWorkspace: string;
  readonly recordType: AutonomousDnsRecordType;
  /** Exact canonical mission criterion supported by the deterministic verifier. */
  readonly successCriterion: string;
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
  if (
    !normalized
    || normalized !== value
    || normalized.length > maximum
    || /[\u0000-\u001F\u007F]/u.test(normalized)
    || SECRET.test(normalized)
  ) {
    throw new TypeError(`${label} must be safe, non-secret text`);
  }
  return normalized;
}

export function validateAutonomousDnsSafeReconConfiguration(
  input: AutonomousDnsSafeReconConfiguration,
  manifest: LocalToolCapabilityManifest,
): AutonomousDnsSafeReconConfiguration {
  const tool = manifest.resolve(AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID);
  if (
    !tool
    || tool.activation !== "enabled"
    || !tool.actionClassIds.includes(AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS)
    || !tool.evidenceTypeIds.includes(AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE)
    || tool.routing.intent !== "dns_query"
    || tool.routing.targetKind !== "domain"
    || tool.execution.transport !== "direct_spawn_argv"
    || tool.execution.shell !== false
    || tool.execution.networkPolicy !== "authorized_scope_only"
    || tool.execution.filesystemWritePolicy !== "resolved_workspace_only"
    || tool.execution.logicalWorkspaceParameter !== "workspace"
  ) {
    throw new Error(
      "The reviewed local manifest does not expose the exact DNS Safe Recon boundary",
    );
  }
  const parameterNames = tool.parameters.map(({ name }) => name).sort();
  if (parameterNames.join("\u0000") !== ["name", "recordType", "workspace"].sort().join("\u0000")) {
    throw new Error("The reviewed DNS tool parameter schema drifted from the exact Safe Recon binding");
  }
  if (!(AUTONOMOUS_DNS_RECORD_TYPES as readonly string[]).includes(input.recordType)) {
    throw new TypeError("Autonomous DNS record type is unsupported");
  }
  if (!SHA256.test(input.modelConfigurationHash)) {
    throw new TypeError("Autonomous DNS model configuration hash must be SHA-256");
  }
  if (input.recordType !== "A" || input.successCriterion !== AUTONOMOUS_DNS_A_SUCCESS_CRITERION) {
    throw new TypeError(
      "Autonomous DNS must use the canonical registry-backed A-record success criterion",
    );
  }
  return Object.freeze({
    policyId: safeId(input.policyId, "policyId"),
    bindingId: safeId(input.bindingId, "bindingId"),
    agentId: safeId(input.agentId, "agentId"),
    providerId: safeId(input.providerId, "providerId"),
    modelId: safeId(input.modelId, "modelId"),
    modelConfigurationHash: input.modelConfigurationHash,
    ...(input.mcpServerId === undefined
      ? {}
      : { mcpServerId: safeId(input.mcpServerId, "mcpServerId") }),
    logicalWorkspace: safeText(input.logicalWorkspace, "logicalWorkspace", 4_096),
    recordType: input.recordType,
    successCriterion: safeText(input.successCriterion, "successCriterion", 2_000),
  });
}

/**
 * Builds one and only one reviewed plan route. This policy is definition-only:
 * it cannot make a provider, specialist, executable, or action boundary
 * ready. The production composition inspector must still attest each live
 * dependency of the reviewed local-process route before activation. Optional
 * MCP inventory is advisory and is never one of those execution dependencies.
 */
export function createAutonomousDnsSafeReconPlanningPolicy(
  input: AutonomousDnsSafeReconConfiguration,
  manifest: LocalToolCapabilityManifest,
): LocalAutonomousPlanningPolicy {
  const configuration = validateAutonomousDnsSafeReconConfiguration(input, manifest);
  return validateLocalAutonomousPlanningPolicy({
    schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
    policyId: configuration.policyId,
    maximumSteps: 1,
    bindings: [{
      bindingId: configuration.bindingId,
      actionClassId: AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
      targetKinds: ["domain"],
      phase: "DNS baseline",
      title: `Check the approved DNS ${configuration.recordType} record`,
      objective: "Record the requested DNS answer, or the attributable absence of that record, for the exact authorized domain.",
      explanation: "Ti-Scale asks the configured DNS resolver for one approved record type. It does not scan ports, authenticate, modify the target, or follow up with another action.",
      rationale: "A bounded DNS lookup establishes a small, attributable reconnaissance fact before any broader target interaction is considered.",
      successCriteria: [configuration.successCriterion],
      reversibility: "The lookup is read-only and creates only local logs, an observation, and—after deterministic validation—immutable evidence.",
      riskClass: "low",
      idempotent: true,
      destructive: false,
      agentId: configuration.agentId,
      providerId: configuration.providerId,
      modelId: configuration.modelId,
      modelConfigurationHash: configuration.modelConfigurationHash,
      executionBinding: "reviewed_local_process",
      toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
      targetParameter: "name",
      staticParameters: {
        workspace: configuration.logicalWorkspace,
        recordType: configuration.recordType,
      },
      capabilityIds: [`capability:${AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID}`],
      requiredEvidenceTypeIds: [AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE],
    }],
  });
}

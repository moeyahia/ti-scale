import {
  EVIDENCE_TYPE_IDS,
  type ActionClassId,
  type EvidenceTypeId,
} from "./catalog-ids";
import type {
  EvidenceCapabilityMapping,
  RuntimeCapabilityProjection,
} from "./source-manifest-adapters";

export const INTELLIGENCE_STAGES = [
  "engagement_log",
  "observation",
  "evidence_candidate",
  "verified_evidence",
  "artifact",
] as const;

export type IntelligenceStage = (typeof INTELLIGENCE_STAGES)[number];

export interface EvidenceTypeDefinition {
  readonly id: EvidenceTypeId;
  readonly label: string;
  readonly proves: string;
  readonly storageAndSensitivity: string;
  readonly normallyRequiredForActionClassIds: readonly ActionClassId[];
  readonly immutableHashRequired: boolean;
  readonly chainOfCustodyRequired: boolean;
}

export interface RegisteredEvidenceType extends EvidenceTypeDefinition {
  readonly capability: EvidenceCapabilityMapping;
}

export interface EvidenceTypeRegistry {
  readonly types: Readonly<Record<EvidenceTypeId, RegisteredEvidenceType>>;
}

const e = (
  id: EvidenceTypeId,
  label: string,
  proves: string,
  storageAndSensitivity: string,
  normallyRequiredForActionClassIds: readonly ActionClassId[],
  chainOfCustodyRequired = true,
): EvidenceTypeDefinition => ({
  id,
  label,
  proves,
  storageAndSensitivity,
  normallyRequiredForActionClassIds,
  immutableHashRequired: true,
  chainOfCustodyRequired,
});

export const EVIDENCE_TYPE_DEFINITIONS: readonly EvidenceTypeDefinition[] = [
  e(
    "asset_discovery_proof",
    "Host or asset discovery proof",
    "An approved asset was observed at a specific time and scope.",
    "May contain client identifiers and network addressing.",
    ["passive_intelligence_osint", "active_host_discovery"],
  ),
  e(
    "port_service_scan_result",
    "Port and service scan result",
    "A transport endpoint was observed in a stated scan context.",
    "Contains network topology and service exposure data.",
    ["port_service_enumeration"],
  ),
  e(
    "service_version_fingerprint",
    "Service and version fingerprint",
    "A product or version was observed, including how strongly it was identified.",
    "May expose patch posture and attack surface.",
    ["port_service_enumeration", "os_technology_fingerprinting"],
  ),
  e(
    "os_platform_fingerprint",
    "OS, kernel, or platform fingerprint",
    "An operating platform or kernel was observed or verified.",
    "May expose host inventory and patch posture.",
    ["os_technology_fingerprinting"],
  ),
  e(
    "dns_certificate_record",
    "DNS or certificate record",
    "A name, resolution, certificate, or TLS identity was observed.",
    "May contain internal names and organization metadata.",
    ["dns_domain_certificate_discovery"],
  ),
  e(
    "http_exchange",
    "HTTP request and response pair",
    "An exact web behavior occurred for a normalized request and response.",
    "Bodies and headers require redaction and disclosure classification.",
    ["web_crawling_page_capture", "authentication_testing"],
  ),
  e(
    "web_page_capture",
    "Web-page capture",
    "A page rendered or responded in a specific state at a specific time.",
    "Screenshots can contain personal, credential, or confidential content.",
    ["web_crawling_page_capture"],
  ),
  e(
    "endpoint_discovery_result",
    "Endpoint or content discovery result",
    "A route, file, parameter, or API endpoint was discovered.",
    "May reveal private application structure and identifiers.",
    ["web_content_endpoint_discovery_fuzzing"],
  ),
  e(
    "configuration_snapshot",
    "Configuration snapshot",
    "A relevant configuration value or security posture was observed.",
    "Must redact secrets and may require local-only storage.",
    ["vulnerability_configuration_assessment", "cloud_container_kubernetes_assessment"],
  ),
  e(
    "cve_applicability",
    "CVE applicability evidence",
    "Observed component evidence was compared with authoritative affected ranges.",
    "Contains product inventory and authoritative-source metadata.",
    ["cve_intelligence_applicability_validation"],
  ),
  e(
    "exploit_validation_result",
    "Exploit-validation result",
    "A bounded validation attempt had an attributable outcome.",
    "High-sensitivity operational data; preserve rollback and exact scope.",
    ["exploit_validation", "privilege_escalation"],
  ),
  e(
    "session_command_outcome",
    "Session or command outcome",
    "A specific authorized command or session action produced a meaningful outcome.",
    "May contain secrets or target data and requires strict redaction.",
    ["command_session_execution", "cleanup_restoration"],
  ),
  e(
    "privilege_access_proof",
    "Privilege or access proof",
    "A defined access level or boundary was demonstrated.",
    "Critical sensitivity; retain the minimum proof needed.",
    ["privilege_escalation", "lateral_movement_pivoting", "data_access_impact_validation"],
  ),
  e(
    "identity_ad_graph",
    "Identity or Active Directory graph evidence",
    "A directory object, permission, trust, or identity path was observed.",
    "Contains sensitive identity and relationship data.",
    ["active_directory_identity_operations"],
  ),
  e(
    "cloud_container_scan",
    "Cloud, container, or cluster scan evidence",
    "A cloud or workload configuration and identity context was observed.",
    "May contain tenant, workload, and account identifiers.",
    ["cloud_container_kubernetes_assessment"],
  ),
  e(
    "binary_analysis",
    "Binary-analysis evidence",
    "A static or dynamic binary property was reproduced.",
    "Binaries may be proprietary or malicious; isolate previews and storage.",
    ["reverse_engineering_binary_analysis", "fuzzing_crash_discovery"],
  ),
  e(
    "hashed_file_artifact",
    "File or artifact with hash",
    "An exact file version existed and is integrity-addressable.",
    "Sensitivity follows the file; large content remains in the artifact store.",
    ["target_file_write", "local_report_artifact_generation"],
  ),
  e(
    "generated_script_validation",
    "Generated-script source and validation",
    "A script version, diff, tests, and execution result are linked.",
    "Source may contain target details; secrets must never be embedded.",
    ["target_file_write", "command_session_execution"],
  ),
  e(
    "finding_reproduction",
    "Finding reproduction evidence",
    "A finding can be reproduced or safely validated under stated prerequisites.",
    "May contain exploit details; apply finding and disclosure policy.",
    ["vulnerability_configuration_assessment", "exploit_validation"],
  ),
  e(
    "chain_of_custody",
    "Chain-of-custody record",
    "Evidence acquisition, hashing, transfer, review, and lifecycle are traceable.",
    "Metadata is immutable and retained under audit policy.",
    ["local_report_artifact_generation"],
  ),
  e(
    "operator_supplied",
    "Operator-supplied evidence",
    "The operator supplied an item and its source is explicitly attributed.",
    "Classification is required before reusable or public-provider use.",
    [],
  ),
] as const;

export function buildEvidenceTypeRegistry(
  projection: RuntimeCapabilityProjection,
): EvidenceTypeRegistry {
  const types = Object.fromEntries(
    EVIDENCE_TYPE_DEFINITIONS.map((definition) => [
      definition.id,
      { ...definition, capability: projection.evidenceTypes[definition.id] },
    ]),
  ) as Record<EvidenceTypeId, RegisteredEvidenceType>;
  return { types };
}

export const OPERATIONAL_INPUT_KINDS = [
  "raw_command_output",
  "structured_scan_result",
  "screenshot",
  "http_exchange",
  "generated_file",
  "operator_upload",
  "parsed_observation",
] as const;

export type OperationalInputKind = (typeof OPERATIONAL_INPUT_KINDS)[number];

export interface OperationalInputClassification {
  readonly kind: OperationalInputKind;
  readonly stages: readonly IntelligenceStage[];
  readonly automaticallyVerified: false;
  readonly reasons: readonly string[];
}

export interface OperationalInputContext {
  readonly parsed: boolean;
  readonly attributable: boolean;
  readonly provenanceSourceIds: readonly string[];
  readonly immutableHash?: string;
  readonly completeRequestResponsePair?: boolean;
  readonly policyAllowsCandidate?: boolean;
}

export function classifyOperationalInput(
  kind: OperationalInputKind,
  context: OperationalInputContext,
): OperationalInputClassification {
  const stages = new Set<IntelligenceStage>();
  const reasons: string[] = [];

  if (kind === "raw_command_output") {
    stages.add("engagement_log");
    reasons.push("Raw command output remains an Engagement Log record by default.");
    return { kind, stages: [...stages], automaticallyVerified: false, reasons };
  }

  if (kind === "structured_scan_result") {
    stages.add("engagement_log");
    stages.add("artifact");
    if (context.parsed && context.attributable) {
      stages.add("observation");
    } else {
      reasons.push("A structured scan needs parsed, attributable observations.");
    }
    reasons.push("A scan artifact is not automatically promoted to evidence.");
  }

  if (kind === "screenshot") {
    stages.add("artifact");
  }

  if (kind === "http_exchange") {
    stages.add("engagement_log");
    if (context.parsed && context.attributable) stages.add("observation");
    if (!context.completeRequestResponsePair) {
      reasons.push("Evidence promotion requires a complete request and response pair.");
    }
  }

  if (kind === "generated_file" || kind === "operator_upload") {
    stages.add("artifact");
  }

  if (kind === "parsed_observation") {
    if (context.parsed && context.attributable) {
      stages.add("observation");
    } else {
      reasons.push("An observation must be parsed and attributable.");
    }
  }

  const candidateKindAllowed =
    kind === "screenshot" ||
    kind === "http_exchange" ||
    kind === "operator_upload" ||
    kind === "parsed_observation";
  const completeForKind =
    kind !== "http_exchange" || context.completeRequestResponsePair === true;
  const candidateGate =
    candidateKindAllowed &&
    context.policyAllowsCandidate === true &&
    context.parsed &&
    context.attributable &&
    context.provenanceSourceIds.length > 0 &&
    context.immutableHash !== undefined &&
    completeForKind;

  if (candidateGate) {
    stages.add("evidence_candidate");
  } else if (candidateKindAllowed) {
    reasons.push("Candidate promotion gates were not all satisfied.");
  }

  return {
    kind,
    stages: [...stages],
    automaticallyVerified: false,
    reasons,
  };
}

export interface EvidenceRecord {
  readonly id: string;
  readonly typeId: EvidenceTypeId;
  readonly stage: IntelligenceStage;
  readonly immutableHash?: string;
  readonly provenanceSourceIds: readonly string[];
  readonly acquiredAt?: string;
  readonly targetId?: string;
  readonly chainOfCustodyComplete: boolean;
  readonly verificationActorId?: string;
}

export interface EvidenceVerificationResult {
  readonly verified: boolean;
  readonly reasons: readonly string[];
  readonly evidence?: EvidenceRecord & {
    readonly stage: "verified_evidence";
    readonly verificationActorId: string;
  };
}

export function verifyEvidenceCandidate(
  candidate: EvidenceRecord,
  definition: EvidenceTypeDefinition,
  verificationActorId: string,
): EvidenceVerificationResult {
  const reasons: string[] = [];
  if (candidate.stage !== "evidence_candidate") {
    reasons.push("Only an evidence candidate can be verified.");
  }
  if (candidate.typeId !== definition.id) {
    reasons.push("Evidence type does not match its verification policy.");
  }
  if (definition.immutableHashRequired && !candidate.immutableHash) {
    reasons.push("An immutable content hash is required.");
  }
  if (candidate.provenanceSourceIds.length === 0) {
    reasons.push("At least one provenance source is required.");
  }
  if (!candidate.acquiredAt) reasons.push("Acquisition time is required.");
  if (!candidate.targetId) reasons.push("A normalized target is required.");
  if (definition.chainOfCustodyRequired && !candidate.chainOfCustodyComplete) {
    reasons.push("Chain of custody is incomplete.");
  }
  if (verificationActorId.trim().length === 0) {
    reasons.push("A distinct verification actor is required.");
  }

  if (reasons.length > 0) return { verified: false, reasons };
  return {
    verified: true,
    reasons: [],
    evidence: {
      ...candidate,
      stage: "verified_evidence",
      verificationActorId,
    },
  };
}

export interface FindingEvidencePolicy {
  readonly requiredEvidenceTypeIds: readonly EvidenceTypeId[];
  readonly requireAtLeastOneVerifiedEvidence: true;
}

export interface FindingVerificationResult {
  readonly verified: boolean;
  readonly missingEvidenceTypeIds: readonly EvidenceTypeId[];
  readonly reasons: readonly string[];
}

export function canVerifyFinding(
  policy: FindingEvidencePolicy,
  linkedEvidence: readonly EvidenceRecord[],
): FindingVerificationResult {
  const verifiedEvidence = linkedEvidence.filter(
    (evidence) =>
      evidence.stage === "verified_evidence" &&
      evidence.immutableHash !== undefined &&
      evidence.provenanceSourceIds.length > 0 &&
      evidence.chainOfCustodyComplete &&
      evidence.verificationActorId !== undefined &&
      evidence.verificationActorId.trim().length > 0,
  );
  const verifiedTypeIds = new Set(verifiedEvidence.map(({ typeId }) => typeId));
  const missingEvidenceTypeIds = policy.requiredEvidenceTypeIds.filter(
    (typeId) => !verifiedTypeIds.has(typeId),
  );
  const reasons: string[] = [];
  if (policy.requireAtLeastOneVerifiedEvidence && verifiedEvidence.length === 0) {
    reasons.push("A finding requires at least one linked verified evidence item.");
  }
  if (missingEvidenceTypeIds.length > 0) {
    reasons.push(`Required evidence is missing: ${missingEvidenceTypeIds.join(", ")}.`);
  }
  return {
    verified: reasons.length === 0,
    missingEvidenceTypeIds,
    reasons,
  };
}

if (EVIDENCE_TYPE_DEFINITIONS.length !== EVIDENCE_TYPE_IDS.length) {
  throw new Error("Every canonical evidence type must have exactly one definition.");
}

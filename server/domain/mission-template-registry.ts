import type {
  ActionClassId,
  DeliverableId,
  EvidenceTypeId,
  Journey,
} from "./catalog-ids";
import type { ActionPolicyPresetId } from "./action-class-registry";
import { AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS } from "./autonomous-outcome-registry";
import type { RuntimeCapabilityProjection } from "./source-manifest-adapters";

export const MISSION_TEMPLATE_IDS = [
  "safe_recon",
  "external_web_assessment",
  "internal_network_assessment",
  "active_directory_lab",
  "cloud_read_only",
  "htb_web_full_path",
  "full_authorized_lab_compromise",
  "custom",
] as const;

export type MissionTemplateId = (typeof MISSION_TEMPLATE_IDS)[number];

export interface MissionTarget {
  readonly id: string;
  readonly type:
    | "host"
    | "cidr"
    | "url"
    | "domain"
    | "cloud_account"
    | "scope_file"
    | "engagement"
    | "lab_environment";
  readonly value: string;
  readonly excluded?: boolean;
}

export interface MissionTemplate {
  readonly id: MissionTemplateId;
  readonly version: number;
  readonly label: string;
  readonly summary: string;
  readonly supportedJourneys: readonly Journey[];
  readonly actionPolicyPresetId: ActionPolicyPresetId;
  readonly scopeHints: readonly string[];
  readonly objectivePattern: string;
  readonly successCriteria: readonly string[];
  readonly recommendedActionClassIds: readonly ActionClassId[];
  readonly recommendedEvidenceTypeIds: readonly EvidenceTypeId[];
  readonly recommendedDeliverableIds: readonly DeliverableId[];
  readonly recommendedOptionalSafeStops: readonly string[];
  readonly recommendedAgentCapabilityIds: readonly string[];
  readonly modelReadinessRequirements: readonly string[];
  readonly budgetPreset: "quick" | "standard" | "deep" | "custom";
}

export interface RegisteredMissionTemplate extends MissionTemplate {
  readonly unsupportedActionClassIds: readonly ActionClassId[];
  readonly unavailableEvidenceTypeIds: readonly EvidenceTypeId[];
  readonly unavailableDeliverableIds: readonly DeliverableId[];
}

export interface MissionTemplateRegistry {
  readonly templates: Readonly<Record<MissionTemplateId, RegisteredMissionTemplate>>;
}

const templates: readonly MissionTemplate[] = [
  {
    id: "safe_recon",
    version: 2,
    label: "Safe Recon",
    summary: "Map approved assets and exposed services without exploit execution.",
    supportedJourneys: ["autonomous", "guided"],
    actionPolicyPresetId: "safe_recon",
    scopeHints: ["Supply only the hosts, networks, URLs, or domains you are authorized to assess."],
    objectivePattern:
      "Map the supplied authorized scope, identify reachable assets and services, validate important fingerprints, and produce evidence-backed reconnaissance outputs without destructive actions.",
    successCriteria: [
      "All supplied targets are discovered or explicitly reported unreachable.",
      "Observed services and versions have attributable supporting evidence.",
      "Unknown or conflicting observations remain visibly unresolved.",
    ],
    recommendedActionClassIds: [
      "passive_intelligence_osint",
      "dns_domain_certificate_discovery",
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "web_crawling_page_capture",
      "web_content_endpoint_discovery_fuzzing",
      "cve_intelligence_applicability_validation",
      "local_report_artifact_generation",
    ],
    recommendedEvidenceTypeIds: [
      "asset_discovery_proof",
      "port_service_scan_result",
      "service_version_fingerprint",
      "http_exchange",
      "endpoint_discovery_result",
      "os_platform_fingerprint",
      "dns_certificate_record",
    ],
    recommendedDeliverableIds: [
      "executive_summary",
      "network_asset_map",
      "cve_applicability_register",
      "machine_readable_export",
    ],
    recommendedOptionalSafeStops: [
      "target_identity_mismatch",
      "target_unreachable",
      "service_instability_detected",
      "budget_reached",
    ],
    recommendedAgentCapabilityIds: ["reconnaissance", "vulnerability_intelligence", "reporting"],
    modelReadinessRequirements: ["structured_output", "tool_calling", "scope_enforcement"],
    budgetPreset: "standard",
  },
  {
    id: "external_web_assessment",
    version: 1,
    label: "External Web Assessment",
    summary: "Assess an approved public web surface with bounded discovery and validation.",
    supportedJourneys: ["autonomous", "guided"],
    actionPolicyPresetId: "external_web_assessment",
    scopeHints: ["Use explicit domains and URLs; add excluded subdomains or third-party services."],
    objectivePattern:
      "Evaluate the supplied authorized web targets for authentication, authorization, input-validation, exposed-service, and configuration weaknesses without destructive actions.",
    successCriteria: [
      "Important applications and endpoints are captured.",
      "Candidate vulnerabilities are classified by applicability and confidence.",
      "Every verified finding is linked to required evidence.",
    ],
    recommendedActionClassIds: [
      "dns_domain_certificate_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "web_crawling_page_capture",
      "web_content_endpoint_discovery_fuzzing",
      "vulnerability_configuration_assessment",
      "cve_intelligence_applicability_validation",
    ],
    recommendedEvidenceTypeIds: [
      "dns_certificate_record",
      "service_version_fingerprint",
      "http_exchange",
      "web_page_capture",
      "endpoint_discovery_result",
      "cve_applicability",
    ],
    recommendedDeliverableIds: [
      "technical_findings",
      "web_page_screenshot_gallery",
      "cve_applicability_register",
      "remediation_plan",
      "pdf_html_markdown_report",
    ],
    recommendedOptionalSafeStops: [
      "service_instability_detected",
      "credential_attempt_threshold_reached",
      "named_business_process_encountered",
      "evidence_insufficient_to_proceed",
    ],
    recommendedAgentCapabilityIds: ["web", "reconnaissance", "vulnerability_intelligence"],
    modelReadinessRequirements: ["structured_output", "tool_calling", "scope_enforcement"],
    budgetPreset: "standard",
  },
  {
    id: "internal_network_assessment",
    version: 1,
    label: "Internal Network Assessment",
    summary: "Map and assess explicitly approved internal network ranges.",
    supportedJourneys: ["autonomous", "guided"],
    actionPolicyPresetId: "internal_network_assessment",
    scopeHints: ["Supply authorized CIDRs and explicitly exclude sensitive infrastructure."],
    objectivePattern:
      "Assess the supplied authorized internal network, map assets and services, validate safe attack paths, and stop at the agreed access boundary.",
    successCriteria: [
      "Approved address space is reconciled with reachable and unreachable assets.",
      "Services, identity surfaces, and viable safe attack paths are documented.",
      "Failed approaches and remaining uncertainty are preserved.",
    ],
    recommendedActionClassIds: [
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "vulnerability_configuration_assessment",
      "cve_intelligence_applicability_validation",
    ],
    recommendedEvidenceTypeIds: [
      "asset_discovery_proof",
      "port_service_scan_result",
      "service_version_fingerprint",
      "configuration_snapshot",
    ],
    recommendedDeliverableIds: [
      "network_asset_map",
      "osi_application_stack_map",
      "attack_path_visualization",
      "technical_findings",
      "remediation_plan",
    ],
    recommendedOptionalSafeStops: [
      "service_instability_detected",
      "target_identity_mismatch",
      "target_unreachable",
      "required_dependency_unavailable",
    ],
    recommendedAgentCapabilityIds: ["reconnaissance", "network", "credentials"],
    modelReadinessRequirements: ["structured_output", "tool_calling", "scope_enforcement"],
    budgetPreset: "deep",
  },
  {
    id: "active_directory_lab",
    version: 1,
    label: "Active Directory Lab",
    summary: "Map and validate identity attack paths in a named authorized lab.",
    supportedJourneys: ["autonomous", "guided"],
    actionPolicyPresetId: "active_directory_lab",
    scopeHints: ["Name the disposable domain, controllers, network boundary, and stopping privilege level."],
    objectivePattern:
      "Map the supplied authorized Active Directory lab, identify viable privilege and lateral paths, and stop at the agreed proof boundary.",
    successCriteria: [
      "Relevant identities, trusts, services, and permissions are mapped.",
      "Viable paths distinguish prerequisites from validated outcomes.",
      "Access proof does not exceed the supplied stopping boundary.",
    ],
    recommendedActionClassIds: [
      "active_host_discovery",
      "port_service_enumeration",
      "active_directory_identity_operations",
      "credential_password_hash_assessment",
      "cve_intelligence_applicability_validation",
    ],
    recommendedEvidenceTypeIds: [
      "identity_ad_graph",
      "privilege_access_proof",
      "session_command_outcome",
      "chain_of_custody",
    ],
    recommendedDeliverableIds: [
      "network_asset_map",
      "attack_path_visualization",
      "technical_findings",
      "remediation_plan",
      "obsidian_engagement_pack",
    ],
    recommendedOptionalSafeStops: [
      "credential_attempt_threshold_reached",
      "specified_high_value_objective_achieved",
      "service_instability_detected",
    ],
    recommendedAgentCapabilityIds: ["active_directory", "credentials", "reconnaissance"],
    modelReadinessRequirements: ["structured_output", "tool_calling", "scope_enforcement"],
    budgetPreset: "deep",
  },
  {
    id: "cloud_read_only",
    version: 1,
    label: "Cloud Read-Only",
    summary: "Assess supplied cloud scope using read-only actions.",
    supportedJourneys: ["autonomous", "guided"],
    actionPolicyPresetId: "cloud_read_only",
    scopeHints: ["Supply exact account, project, subscription, cluster, and region boundaries."],
    objectivePattern:
      "Assess the supplied authorized cloud scope using read-only operations, identify exposure and privilege paths, and produce evidence-backed remediation guidance.",
    successCriteria: [
      "Supplied accounts and projects are reconciled with observed resources.",
      "Identity, network, data, and workload findings retain source evidence.",
      "No mutation action is executed.",
    ],
    recommendedActionClassIds: [
      "passive_intelligence_osint",
      "cloud_container_kubernetes_assessment",
      "vulnerability_configuration_assessment",
      "cve_intelligence_applicability_validation",
    ],
    recommendedEvidenceTypeIds: [
      "cloud_container_scan",
      "configuration_snapshot",
      "cve_applicability",
    ],
    recommendedDeliverableIds: [
      "technical_findings",
      "network_asset_map",
      "remediation_plan",
      "machine_readable_export",
    ],
    recommendedOptionalSafeStops: [
      "target_identity_mismatch",
      "required_dependency_unavailable",
      "evidence_insufficient_to_proceed",
    ],
    recommendedAgentCapabilityIds: ["cloud", "containers", "vulnerability_intelligence"],
    modelReadinessRequirements: ["structured_output", "tool_calling", "scope_enforcement"],
    budgetPreset: "standard",
  },
  {
    id: "htb_web_full_path",
    version: 2,
    label: "HTB Web Full Path",
    summary:
      "Run the exact-host web assessment path through candidate-bound validation, independently verified user and root access proofs, and bounded cleanup when every dependency is attested.",
    supportedJourneys: ["autonomous", "guided"],
    actionPolicyPresetId: "htb_web_full_path",
    scopeHints: [
      "Supply one exact disposable HTB, CTF, or local-lab host; the template never supplies or expands targets.",
      "Exploit validation remains unavailable until current version evidence, an exact Vault candidate, the sandbox, and an independent target-impact observer all agree.",
      "Post-exploit work is materialized only when the signed contract and attested candidate transport expose every required class; no general shell is created.",
    ],
    objectivePattern:
      "Map the supplied disposable host, fingerprint its reachable web stack, assess evidence-backed weaknesses, run at most one approved evidence-matched validation, prove user and root access without retaining flag content, then clean up the bounded candidate session.",
    successCriteria: [
      "The exact host has a complete TCP and service/version baseline.",
      "Responding web surfaces, endpoints, and applicable CVEs retain attributable evidence.",
      "Any validation result is classified only from independent custody-verified target-impact evidence, never process output alone.",
      "User and root objectives are proven with independent identity observations and hash-only flag receipts.",
      "The candidate-bound session is closed and leaves no active execution lease.",
    ],
    recommendedActionClassIds: [
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "web_crawling_page_capture",
      "web_content_endpoint_discovery_fuzzing",
      "vulnerability_configuration_assessment",
      "cve_intelligence_applicability_validation",
      "exploit_validation",
      "command_session_execution",
      "data_access_impact_validation",
      "privilege_escalation",
      "cleanup_restoration",
    ],
    recommendedEvidenceTypeIds: [
      "asset_discovery_proof",
      "port_service_scan_result",
      "service_version_fingerprint",
      "http_exchange",
      "endpoint_discovery_result",
      "configuration_snapshot",
      "cve_applicability",
      "exploit_validation_result",
      "finding_reproduction",
    ],
    recommendedDeliverableIds: [
      "machine_readable_export",
      "pdf_html_markdown_report",
    ],
    recommendedOptionalSafeStops: [
      "target_identity_mismatch",
      "service_instability_detected",
      "required_dependency_unavailable",
      "evidence_insufficient_to_proceed",
      "budget_reached",
    ],
    recommendedAgentCapabilityIds: [
      "reconnaissance",
      "web",
      "vulnerability_intelligence",
      "persistent_execution",
      "reporting",
    ],
    modelReadinessRequirements: ["structured_output", "tool_calling", "scope_enforcement"],
    budgetPreset: "deep",
  },
  {
    id: "full_authorized_lab_compromise",
    version: 1,
    label: "Full Authorized Lab Compromise",
    summary: "Validate an end-to-end path in named disposable lab assets.",
    supportedJourneys: ["autonomous", "guided"],
    actionPolicyPresetId: "full_authorized_lab_compromise",
    scopeHints: ["This preset never supplies targets; name every disposable lab boundary explicitly."],
    objectivePattern:
      "Validate an end-to-end attack path inside the supplied disposable lab scope, stop at the agreed impact boundary, clean up changes, and preserve complete evidence.",
    successCriteria: [
      "At least one safe path is validated when prerequisites exist.",
      "All changes and cleanup actions are recorded and verified.",
      "Destructive and disruptive actions remain prohibited unless separately bounded.",
    ],
    recommendedActionClassIds: [
      "active_host_discovery",
      "port_service_enumeration",
      "vulnerability_configuration_assessment",
      "exploit_validation",
      "command_session_execution",
      "target_file_write",
      "privilege_escalation",
      "lateral_movement_pivoting",
      "cleanup_restoration",
    ],
    recommendedEvidenceTypeIds: [
      "exploit_validation_result",
      "session_command_outcome",
      "privilege_access_proof",
      "generated_script_validation",
      "chain_of_custody",
    ],
    recommendedDeliverableIds: [
      "attack_path_visualization",
      "evidence_bundle",
      "scripts_and_documentation",
      "technical_findings",
      "pdf_html_markdown_report",
    ],
    recommendedOptionalSafeStops: [
      "specified_high_value_objective_achieved",
      "service_instability_detected",
      "budget_reached",
      "evidence_insufficient_to_proceed",
    ],
    recommendedAgentCapabilityIds: [
      "reconnaissance",
      "vulnerability_intelligence",
      "persistent_execution",
      "reporting",
    ],
    modelReadinessRequirements: ["structured_output", "tool_calling", "scope_enforcement"],
    budgetPreset: "deep",
  },
  {
    id: "custom",
    version: 1,
    label: "Custom",
    summary: "Start from safe platform defaults and customize behavior inside supplied scope.",
    supportedJourneys: ["autonomous", "guided"],
    actionPolicyPresetId: "custom",
    scopeHints: ["Templates configure behavior only; authorization always comes from supplied targets."],
    objectivePattern:
      "Assess the supplied authorized scope according to the reviewed mission contract and produce evidence-backed outcomes.",
    successCriteria: ["Every completed claim is traceable to required evidence."],
    recommendedActionClassIds: ["local_report_artifact_generation"],
    recommendedEvidenceTypeIds: ["chain_of_custody"],
    recommendedDeliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
    recommendedOptionalSafeStops: ["budget_reached", "evidence_insufficient_to_proceed"],
    recommendedAgentCapabilityIds: ["reporting"],
    modelReadinessRequirements: ["structured_output", "scope_enforcement"],
    budgetPreset: "custom",
  },
] as const;

export function buildMissionTemplateRegistry(
  projection: RuntimeCapabilityProjection,
  journey: Journey,
): MissionTemplateRegistry {
  const registered = Object.fromEntries(
    templates.map((template): [MissionTemplateId, RegisteredMissionTemplate] => [
      template.id,
      {
        ...template,
        // Autonomous defaults may promise only evidence that the connected
        // runtime can produce now. Guided defaults describe the proof the
        // represented assessment should capture even when the operator will
        // run a step manually or upload the result, so runtime unavailability
        // remains visible metadata rather than silently erasing the contract.
        recommendedEvidenceTypeIds:
          journey === "autonomous"
            ? template.recommendedEvidenceTypeIds.filter(
                (id) => projection.evidenceTypes[id].availability === "supported",
              )
            : template.recommendedEvidenceTypeIds,
        unsupportedActionClassIds: template.recommendedActionClassIds.filter(
          (id) => projection.actionClasses[id].availability === "unsupported",
        ),
        unavailableEvidenceTypeIds: template.recommendedEvidenceTypeIds.filter(
          (id) => projection.evidenceTypes[id].availability !== "supported",
        ),
        unavailableDeliverableIds: template.recommendedDeliverableIds.filter(
          (id) => projection.deliverables[id].availability !== "supported",
        ),
      },
    ]),
  ) as Record<MissionTemplateId, RegisteredMissionTemplate>;
  return { templates: registered };
}

export interface AppliedMissionTemplate {
  readonly templateId: MissionTemplateId;
  readonly templateVersion: number;
  readonly journey: Journey;
  readonly targets: readonly MissionTarget[];
  readonly generatedObjective: string;
  readonly successCriteria: readonly string[];
  readonly recommendedEvidenceTypeIds: readonly EvidenceTypeId[];
  readonly recommendedDeliverableIds: readonly DeliverableId[];
}

export function applyMissionTemplate(
  template: MissionTemplate,
  journey: Journey,
  suppliedTargets: readonly MissionTarget[],
): AppliedMissionTemplate {
  if (!template.supportedJourneys.includes(journey)) {
    throw new Error(`${template.label} does not support the ${journey} journey.`);
  }
  if (suppliedTargets.length === 0) {
    throw new Error("At least one operator-supplied target is required.");
  }
  const targets = suppliedTargets.map((target) => ({ ...target }));
  return {
    templateId: template.id,
    templateVersion: template.version,
    journey,
    targets,
    generatedObjective: template.objectivePattern,
    successCriteria: [...template.successCriteria],
    recommendedEvidenceTypeIds: [...template.recommendedEvidenceTypeIds],
    recommendedDeliverableIds: [...template.recommendedDeliverableIds],
  };
}

export function assertTemplatePreservedTargetScope(
  suppliedTargets: readonly MissionTarget[],
  applied: AppliedMissionTemplate,
): void {
  const before = JSON.stringify(suppliedTargets);
  const after = JSON.stringify(applied.targets);
  if (before !== after) {
    throw new Error("A mission template must never expand or mutate supplied target scope.");
  }
}

export const MISSION_TEMPLATES: readonly MissionTemplate[] = templates;

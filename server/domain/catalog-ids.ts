export const JOURNEYS = ["autonomous", "guided"] as const;

export type Journey = (typeof JOURNEYS)[number];

export const ACTION_CLASS_IDS = [
  "passive_intelligence_osint",
  "dns_domain_certificate_discovery",
  "active_host_discovery",
  "port_service_enumeration",
  "os_technology_fingerprinting",
  "web_crawling_page_capture",
  "web_content_endpoint_discovery_fuzzing",
  "vulnerability_configuration_assessment",
  "cve_intelligence_applicability_validation",
  "credential_password_hash_assessment",
  "authentication_testing",
  "exploit_validation",
  "command_session_execution",
  "target_file_write",
  "privilege_escalation",
  "lateral_movement_pivoting",
  "active_directory_identity_operations",
  "cloud_container_kubernetes_assessment",
  "reverse_engineering_binary_analysis",
  "fuzzing_crash_discovery",
  "data_access_impact_validation",
  "persistence",
  "cleanup_restoration",
  "denial_of_service_disruption",
  "destructive_modification",
  "local_report_artifact_generation",
] as const;

export type ActionClassId = (typeof ACTION_CLASS_IDS)[number];

export const EVIDENCE_TYPE_IDS = [
  "asset_discovery_proof",
  "port_service_scan_result",
  "service_version_fingerprint",
  "os_platform_fingerprint",
  "dns_certificate_record",
  "http_exchange",
  "web_page_capture",
  "endpoint_discovery_result",
  "configuration_snapshot",
  "cve_applicability",
  "exploit_validation_result",
  "session_command_outcome",
  "privilege_access_proof",
  "identity_ad_graph",
  "cloud_container_scan",
  "binary_analysis",
  "hashed_file_artifact",
  "generated_script_validation",
  "finding_reproduction",
  "chain_of_custody",
  "operator_supplied",
] as const;

export type EvidenceTypeId = (typeof EVIDENCE_TYPE_IDS)[number];

export const DELIVERABLE_IDS = [
  "executive_summary",
  "technical_findings",
  "network_asset_map",
  "osi_application_stack_map",
  "attack_path_visualization",
  "engagement_timeline",
  "evidence_bundle",
  "web_page_screenshot_gallery",
  "cve_applicability_register",
  "scripts_and_documentation",
  "remediation_plan",
  "raw_technical_log_export",
  "obsidian_engagement_pack",
  "machine_readable_export",
  "pdf_html_markdown_report",
] as const;

export type DeliverableId = (typeof DELIVERABLE_IDS)[number];

export function isJourney(value: unknown): value is Journey {
  return typeof value === "string" && (JOURNEYS as readonly string[]).includes(value);
}

export function assertJourney(value: unknown): asserts value is Journey {
  if (!isJourney(value)) {
    throw new Error(
      `Invalid mission journey ${JSON.stringify(value)}. Ti-Scale exposes exactly autonomous or guided.`,
    );
  }
}

export function isActionClassId(value: string): value is ActionClassId {
  return (ACTION_CLASS_IDS as readonly string[]).includes(value);
}

export function isEvidenceTypeId(value: string): value is EvidenceTypeId {
  return (EVIDENCE_TYPE_IDS as readonly string[]).includes(value);
}

export function isDeliverableId(value: string): value is DeliverableId {
  return (DELIVERABLE_IDS as readonly string[]).includes(value);
}

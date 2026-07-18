import {
  ACTION_CLASS_IDS,
  assertJourney,
  type ActionClassId,
  type EvidenceTypeId,
  type Journey,
} from "./catalog-ids";
import type {
  ActionCapabilityMapping,
  RuntimeCapabilityProjection,
} from "./source-manifest-adapters";

export const ACTION_POLICY_STATES = [
  "pre_authorized",
  "prohibited",
  "guided_only",
  "inherited_default",
] as const;

export type ActionPolicyState = (typeof ACTION_POLICY_STATES)[number];
export type ResolvedActionPolicyState = Exclude<ActionPolicyState, "inherited_default">;
export type ActionRiskBand = "low" | "moderate" | "high" | "critical";
export type DestructiveActionPolicy =
  | "prohibited"
  | "validate_without_executing"
  | "bounded_lab_only";

export const ACTION_POLICY_PRESET_IDS = [
  "safe_recon",
  "external_web_assessment",
  "internal_network_assessment",
  "active_directory_lab",
  "cloud_read_only",
  "full_authorized_lab_compromise",
  "custom",
] as const;

export type ActionPolicyPresetId = (typeof ACTION_POLICY_PRESET_IDS)[number];

export interface ActionClassDefinition {
  readonly id: ActionClassId;
  readonly label: string;
  readonly plainLanguageDescription: string;
  readonly technicalDescription: string;
  readonly riskBand: ActionRiskBand;
  readonly likelySideEffects: readonly string[];
  readonly defaultPolicyState: ResolvedActionPolicyState;
  readonly defaultEvidenceTypeIds: readonly EvidenceTypeId[];
  readonly destructiveOrDisruptive: boolean;
}

export interface ResolvedActionClass extends ActionClassDefinition {
  readonly policyState: ResolvedActionPolicyState;
  readonly policySource: "platform_default" | "preset" | "operator_override";
  readonly capability: ActionCapabilityMapping;
  readonly launchBlockingReasons: readonly string[];
}

export interface ActionClassRegistry {
  readonly journey: Journey;
  readonly presetId: ActionPolicyPresetId;
  readonly destructivePolicy: DestructiveActionPolicy;
  readonly classes: Readonly<Record<ActionClassId, ResolvedActionClass>>;
  readonly autonomousLaunchReady: boolean;
  readonly launchBlockingReasons: readonly string[];
}

export interface BuildActionClassRegistryInput {
  readonly journey: Journey;
  readonly presetId: ActionPolicyPresetId;
  readonly destructivePolicy: DestructiveActionPolicy;
  readonly projection: RuntimeCapabilityProjection;
  readonly overrides?: Readonly<Partial<Record<ActionClassId, ActionPolicyState>>>;
  readonly authorizedTargetIds?: readonly string[];
  readonly boundedDestructiveTargetIds?: readonly string[];
}

const d = (
  id: ActionClassId,
  label: string,
  plainLanguageDescription: string,
  technicalDescription: string,
  riskBand: ActionRiskBand,
  defaultPolicyState: ResolvedActionPolicyState,
  defaultEvidenceTypeIds: readonly EvidenceTypeId[],
  likelySideEffects: readonly string[] = [],
  destructiveOrDisruptive = false,
): ActionClassDefinition => ({
  id,
  label,
  plainLanguageDescription,
  technicalDescription,
  riskBand,
  defaultPolicyState,
  defaultEvidenceTypeIds,
  likelySideEffects,
  destructiveOrDisruptive,
});

export const ACTION_CLASS_DEFINITIONS: readonly ActionClassDefinition[] = [
  d(
    "passive_intelligence_osint",
    "Passive intelligence and OSINT",
    "Collect public information without directly interacting with the target.",
    "Queries approved public intelligence sources and local datasets.",
    "low",
    "pre_authorized",
    ["asset_discovery_proof"],
  ),
  d(
    "dns_domain_certificate_discovery",
    "DNS, domain, and certificate discovery",
    "Map approved names, records, and certificates.",
    "Performs DNS, registration, certificate-transparency, and TLS metadata discovery.",
    "low",
    "pre_authorized",
    ["dns_certificate_record"],
  ),
  d(
    "active_host_discovery",
    "Active host discovery",
    "Check which approved systems are reachable.",
    "Uses bounded probes within normalized target scope.",
    "moderate",
    "guided_only",
    ["asset_discovery_proof"],
    ["May create observable network traffic."],
  ),
  d(
    "port_service_enumeration",
    "Port and service enumeration",
    "Identify reachable services on approved systems.",
    "Performs bounded TCP/UDP enumeration and service probing.",
    "moderate",
    "guided_only",
    ["port_service_scan_result", "service_version_fingerprint"],
    ["May trigger monitoring or rate controls."],
  ),
  d(
    "os_technology_fingerprinting",
    "Operating-system and technology fingerprinting",
    "Identify platforms and products using attributable observations.",
    "Correlates banners, protocol behavior, package metadata, and active fingerprints.",
    "moderate",
    "guided_only",
    ["os_platform_fingerprint", "service_version_fingerprint"],
  ),
  d(
    "web_crawling_page_capture",
    "Web crawling and page capture",
    "Discover and capture approved web pages.",
    "Crawls normalized HTTP/S scope and creates hashed page-capture artifacts.",
    "moderate",
    "guided_only",
    ["http_exchange", "web_page_capture"],
    ["May create application requests and store sensitive page content."],
  ),
  d(
    "web_content_endpoint_discovery_fuzzing",
    "Web content and endpoint discovery",
    "Look for approved hidden routes, files, and inputs.",
    "Performs bounded endpoint discovery and parameter/content fuzzing.",
    "high",
    "guided_only",
    ["endpoint_discovery_result", "http_exchange"],
    ["May generate high request volume or trigger application defenses."],
  ),
  d(
    "vulnerability_configuration_assessment",
    "Vulnerability and configuration assessment",
    "Assess observed services and configurations for weaknesses.",
    "Runs policy-bounded scanners and configuration analyzers without assuming findings are verified.",
    "moderate",
    "guided_only",
    ["configuration_snapshot", "finding_reproduction"],
  ),
  d(
    "cve_intelligence_applicability_validation",
    "CVE intelligence and applicability validation",
    "Compare verified product evidence with authoritative vulnerability information.",
    "Performs version/CPE matching and applicability classification with source provenance.",
    "low",
    "pre_authorized",
    ["cve_applicability", "service_version_fingerprint"],
  ),
  d(
    "credential_password_hash_assessment",
    "Credential, password, and hash assessment",
    "Audit explicitly supplied credentials or captured hashes within policy.",
    "Performs bounded password, hash, and credential-quality assessment.",
    "high",
    "guided_only",
    ["session_command_outcome", "finding_reproduction"],
    ["Can cause lockouts or expose sensitive authentication material."],
  ),
  d(
    "authentication_testing",
    "Authentication testing",
    "Validate approved authentication controls without exceeding attempt limits.",
    "Exercises bounded login, token, SSO, or identity flows.",
    "high",
    "guided_only",
    ["http_exchange", "session_command_outcome"],
    ["Can trigger lockouts, alerts, or session invalidation."],
  ),
  d(
    "exploit_validation",
    "Exploit validation",
    "Safely validate whether an observed weakness has authorized impact.",
    "Executes bounded proof procedures with prerequisites, evidence gates, and rollback notes.",
    "high",
    "guided_only",
    ["exploit_validation_result", "finding_reproduction"],
    ["May alter process, application, or session state."],
  ),
  d(
    "command_session_execution",
    "Command and session execution",
    "Run bounded commands through an authorized session.",
    "Creates and supervises remote/local execution actions with exact scope and cancellation.",
    "high",
    "guided_only",
    ["session_command_outcome"],
    ["Commands may change target state."],
  ),
  d(
    "target_file_write",
    "Target file upload or write",
    "Create or modify a file only where explicitly allowed.",
    "Transfers or writes content with hashing, path policy, cleanup, and provenance.",
    "high",
    "guided_only",
    ["hashed_file_artifact", "generated_script_validation"],
    ["Changes target filesystem state."],
  ),
  d(
    "privilege_escalation",
    "Privilege escalation",
    "Validate an authorized path to higher privileges.",
    "Exercises a bounded local or identity privilege-escalation technique.",
    "critical",
    "guided_only",
    ["privilege_access_proof", "exploit_validation_result"],
    ["May materially change access or process state."],
  ),
  d(
    "lateral_movement_pivoting",
    "Lateral movement and pivoting",
    "Move through explicitly approved systems or network paths.",
    "Establishes bounded remote execution, relay, tunnel, or pivot paths.",
    "critical",
    "guided_only",
    ["privilege_access_proof", "session_command_outcome"],
    ["Can expand operational reach inside the supplied scope."],
  ),
  d(
    "active_directory_identity_operations",
    "Active Directory and identity operations",
    "Assess approved identities, trusts, and domain attack paths.",
    "Performs directory enumeration and bounded identity-control validation.",
    "high",
    "guided_only",
    ["identity_ad_graph", "privilege_access_proof"],
  ),
  d(
    "cloud_container_kubernetes_assessment",
    "Cloud, container, and Kubernetes assessment",
    "Assess explicitly supplied cloud or orchestration environments.",
    "Queries and validates cloud, container, cluster, namespace, identity, and workload controls.",
    "high",
    "guided_only",
    ["cloud_container_scan", "configuration_snapshot"],
  ),
  d(
    "reverse_engineering_binary_analysis",
    "Reverse engineering and binary analysis",
    "Analyze approved software or binaries in an isolated workspace.",
    "Performs static/dynamic binary inspection, decompilation, and behavior analysis.",
    "moderate",
    "guided_only",
    ["binary_analysis", "hashed_file_artifact"],
  ),
  d(
    "fuzzing_crash_discovery",
    "Fuzzing and crash discovery",
    "Run bounded malformed-input tests in an authorized environment.",
    "Executes instrumented fuzz campaigns with time, crash, and resource budgets.",
    "high",
    "guided_only",
    ["binary_analysis", "finding_reproduction"],
    ["May crash the tested process or consume substantial resources."],
  ),
  d(
    "data_access_impact_validation",
    "Data-access impact validation",
    "Prove the authorized boundary of data access without unnecessary collection.",
    "Validates access controls using minimization, redaction, and evidence policy.",
    "critical",
    "guided_only",
    ["privilege_access_proof", "finding_reproduction"],
    ["May encounter confidential data."],
  ),
  d(
    "persistence",
    "Persistence",
    "Validate a persistence path only in a specifically authorized disposable lab.",
    "Creates a bounded persistence mechanism with mandatory cleanup verification.",
    "critical",
    "prohibited",
    ["session_command_outcome", "finding_reproduction"],
    ["Changes durable target state and may survive process restart."],
    true,
  ),
  d(
    "cleanup_restoration",
    "Cleanup and restoration",
    "Remove authorized test changes and verify restoration.",
    "Runs declared rollback and cleanup procedures with before/after evidence.",
    "high",
    "guided_only",
    ["session_command_outcome", "configuration_snapshot"],
    ["Incorrect cleanup may remove legitimate data."],
  ),
  d(
    "denial_of_service_disruption",
    "Denial of service or disruption",
    "Attempt service disruption only under a separately bounded lab policy.",
    "Executes availability-impacting actions against named disposable assets.",
    "critical",
    "prohibited",
    ["session_command_outcome", "finding_reproduction"],
    ["Can degrade or stop a service."],
    true,
  ),
  d(
    "destructive_modification",
    "Destructive data or system modification",
    "Destroy or irreversibly alter data only under a separately bounded lab policy.",
    "Performs destructive modification against named disposable assets with explicit bounds.",
    "critical",
    "prohibited",
    ["session_command_outcome", "finding_reproduction"],
    ["Can cause irreversible data or system loss."],
    true,
  ),
  d(
    "local_report_artifact_generation",
    "Local report and artifact generation",
    "Generate local mission reports and exports.",
    "Builds hashed reports, summaries, maps, and evidence-package metadata locally.",
    "low",
    "pre_authorized",
    ["hashed_file_artifact", "chain_of_custody"],
  ),
] as const;

const SAFE_RECON_PREAUTHORIZED: readonly ActionClassId[] = [
  "passive_intelligence_osint",
  "dns_domain_certificate_discovery",
  "active_host_discovery",
  "port_service_enumeration",
  "os_technology_fingerprinting",
  "cve_intelligence_applicability_validation",
  "local_report_artifact_generation",
];

const PRESET_PREAUTHORIZED: Readonly<
  Record<ActionPolicyPresetId, readonly ActionClassId[]>
> = {
  safe_recon: SAFE_RECON_PREAUTHORIZED,
  external_web_assessment: [
    ...SAFE_RECON_PREAUTHORIZED,
    "web_crawling_page_capture",
    "web_content_endpoint_discovery_fuzzing",
    "vulnerability_configuration_assessment",
  ],
  internal_network_assessment: [
    ...SAFE_RECON_PREAUTHORIZED,
    "vulnerability_configuration_assessment",
  ],
  active_directory_lab: [
    ...SAFE_RECON_PREAUTHORIZED,
    "vulnerability_configuration_assessment",
    "active_directory_identity_operations",
  ],
  cloud_read_only: [
    "passive_intelligence_osint",
    "dns_domain_certificate_discovery",
    "cloud_container_kubernetes_assessment",
    "cve_intelligence_applicability_validation",
    "local_report_artifact_generation",
  ],
  full_authorized_lab_compromise: [
    ...SAFE_RECON_PREAUTHORIZED,
    "web_crawling_page_capture",
    "web_content_endpoint_discovery_fuzzing",
    "vulnerability_configuration_assessment",
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
    "cleanup_restoration",
  ],
  custom: [],
};

function resolvePolicy(
  definition: ActionClassDefinition,
  presetId: ActionPolicyPresetId,
  override: ActionPolicyState | undefined,
): Pick<ResolvedActionClass, "policyState" | "policySource"> {
  if (override !== undefined && override !== "inherited_default") {
    return { policyState: override, policySource: "operator_override" };
  }
  if (PRESET_PREAUTHORIZED[presetId].includes(definition.id)) {
    return { policyState: "pre_authorized", policySource: "preset" };
  }
  return {
    policyState: definition.defaultPolicyState,
    policySource: "platform_default",
  };
}

export function buildActionClassRegistry(
  input: BuildActionClassRegistryInput,
): ActionClassRegistry {
  assertJourney(input.journey);
  const authorizedTargets = new Set(input.authorizedTargetIds ?? []);
  const boundedTargets = input.boundedDestructiveTargetIds ?? [];
  const invalidBoundedTargets = boundedTargets.filter((targetId) => !authorizedTargets.has(targetId));
  if (invalidBoundedTargets.length > 0) {
    throw new Error(
      `Bounded destructive targets are outside supplied authorization: ${invalidBoundedTargets.join(", ")}`,
    );
  }

  const classes = Object.fromEntries(
    ACTION_CLASS_DEFINITIONS.map((definition): [ActionClassId, ResolvedActionClass] => {
      let resolved = resolvePolicy(definition, input.presetId, input.overrides?.[definition.id]);
      const launchBlockingReasons: string[] = [];

      if (definition.destructiveOrDisruptive && resolved.policyState === "pre_authorized") {
        if (
          input.destructivePolicy !== "bounded_lab_only" ||
          boundedTargets.length === 0
        ) {
          resolved = { policyState: "prohibited", policySource: "platform_default" };
          launchBlockingReasons.push(
            "Destructive or disruptive execution remains prohibited without named bounded lab targets.",
          );
        }
      }

      const capability = input.projection.actionClasses[definition.id];
      if (input.journey === "autonomous" && resolved.policyState === "pre_authorized") {
        const executable = capability.availability === "supported" && capability.enforcementReady;
        if (!executable && resolved.policySource !== "operator_override") {
          // Recommended defaults adapt to the attested runtime. An unavailable
          // optional capability is never granted and does not make a safe
          // minimal mission impossible to launch.
          resolved = { policyState: "prohibited", policySource: "platform_default" };
        } else if (!executable) {
          if (capability.availability !== "supported") {
            launchBlockingReasons.push(
              `${definition.label} was explicitly allowed, but the runtime reports it as ${capability.availability}. Connect a supported specialist and tool, or change this class to Guided only or Prohibited.`,
            );
          }
          if (!capability.enforcementReady) {
            launchBlockingReasons.push(
              `${definition.label} was explicitly allowed, but no locally enforced executor can perform it autonomously. Select an enforcing provider and tool path, or change this class to Guided only or Prohibited.`,
            );
          }
        }
      }

      return [
        definition.id,
        {
          ...definition,
          ...resolved,
          capability,
          launchBlockingReasons,
        },
      ];
    }),
  ) as Record<ActionClassId, ResolvedActionClass>;

  const unresolvedSupported = ACTION_CLASS_IDS.filter(
    (id) => classes[id].capability.availability === "supported" && !classes[id].policyState,
  );
  if (unresolvedSupported.length > 0) {
    throw new Error(
      `Supported action classes have unresolved policy: ${unresolvedSupported.join(", ")}`,
    );
  }

  const launchBlockingReasons = ACTION_CLASS_IDS.flatMap((id) =>
    classes[id].launchBlockingReasons,
  );
  if (
    input.journey === "autonomous"
    && !ACTION_CLASS_IDS.some((id) => classes[id].policyState === "pre_authorized")
  ) {
    launchBlockingReasons.push(
      "No supported, locally enforced action class is available for Autonomous execution.",
    );
  }

  return {
    journey: input.journey,
    presetId: input.presetId,
    destructivePolicy: input.destructivePolicy,
    classes,
    autonomousLaunchReady:
      input.journey !== "autonomous" || launchBlockingReasons.length === 0,
    launchBlockingReasons,
  };
}

export function assertAutonomousRegistryLaunchReady(
  registry: ActionClassRegistry,
): ActionClassRegistry {
  if (registry.journey !== "autonomous") {
    throw new Error("Autonomous readiness can only be asserted for an autonomous registry.");
  }
  if (!registry.autonomousLaunchReady) {
    throw new Error(
      `Autonomous action policy is not executable: ${registry.launchBlockingReasons.join("; ")}`,
    );
  }
  return registry;
}

export type AutonomousActionDisposition =
  | "execute_inside_contract"
  | "deny_prohibited"
  | "safe_stop_or_choose_in_scope_alternative";

export function autonomousActionDisposition(
  registry: ActionClassRegistry,
  actionClassId: ActionClassId,
): AutonomousActionDisposition {
  if (registry.journey !== "autonomous") {
    throw new Error("Autonomous disposition requires an autonomous action registry.");
  }
  const policyState = registry.classes[actionClassId].policyState;
  if (policyState === "pre_authorized") return "execute_inside_contract";
  if (policyState === "prohibited") return "deny_prohibited";
  return "safe_stop_or_choose_in_scope_alternative";
}

if (ACTION_CLASS_DEFINITIONS.length !== ACTION_CLASS_IDS.length) {
  throw new Error("Every canonical action class must have exactly one definition.");
}

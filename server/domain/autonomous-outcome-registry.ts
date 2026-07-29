import type { ActionClassId, DeliverableId, EvidenceTypeId } from "./catalog-ids";

export const AUTONOMOUS_DNS_A_SUCCESS_CRITERION =
  "The exact DNS A query has one verified result for the authorized domain" as const;

export const AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION =
  "The exact approved host has one verified bounded liveness result" as const;

export const AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION =
  "The exact approved host has one verified result for the reviewed TCP port set" as const;

export const AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION =
  "Every HTTP origin derived from the verified TCP baseline has one verified bounded metadata result" as const;

export const AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION =
  "Every responding derived HTTP origin has one verified bounded technology fingerprint result" as const;

export const AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION =
  "Every responding derived HTTP origin has one verified bounded endpoint-discovery result" as const;

export const AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION =
  "Every verified service product/version observation has one conservative, authoritative-source-backed CVE applicability assessment" as const;

export const AUTONOMOUS_VULNERABILITY_ASSESSMENT_SUCCESS_CRITERION =
  "Every responding HTTP origin derived from verified current-run evidence has one completed bounded read-only vulnerability and configuration assessment" as const;

export const AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION =
  "The one evidence-matched validation attempt has an independently observed, custody-verified target-impact outcome" as const;

export const AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION =
  "The candidate-bound session has one independent non-root principal and numeric UID/GID identity observation" as const;

export const AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION =
  "The declared user objective has one verified hash-only user.txt proof without retained flag content" as const;

export const AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION =
  "The candidate-bound privilege path has one separate identity observation proving principal root with UID and GID zero" as const;

export const AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION =
  "The declared root objective has one verified hash-only /root/root.txt proof without retained flag content" as const;

export const AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION =
  "The candidate-bound session is closed and no active session lease remains" as const;

/**
 * Exact terminal proof order for the reviewed disposable Linux web path.
 *
 * Action-class order cannot express this sequence because user and root flag
 * proofs share data_access_impact_validation while privilege escalation sits
 * between them. Mission contracts and tests therefore consume this explicit
 * chain rather than accidentally inheriting catalog order.
 */
export const AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA =
  Object.freeze([
    AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
    AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
    AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION,
    AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION,
    AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
    AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
  ] as const);

/**
 * Complete permission set required before the HTB terminal proof chain may
 * become a default mission-completion obligation.
 *
 * This is an eligibility set, not an execution order. The user and root proof
 * steps share data_access_impact_validation on opposite sides of privilege
 * escalation, so the exact runtime sequence remains expressed by
 * AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA and the reviewed
 * planner. If any class is prohibited, exploit validation remains an optional
 * evidence-driven branch and the incomplete terminal chain must not create
 * unsupported mandatory outcomes.
 */
export const AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS =
  Object.freeze([
    "exploit_validation",
    "command_session_execution",
    "data_access_impact_validation",
    "privilege_escalation",
    "cleanup_restoration",
  ] as const satisfies readonly ActionClassId[]);

/**
 * Autonomous remains one user-facing journey. This profile only states what
 * that Autonomous contract promises to finish; it is not a third journey or
 * an internal provider/runtime mode.
 */
export type AutonomousOutcomeProfileId =
  | "assessment"
  | "complete_engagement";

export interface AutonomousOutcomeProfile {
  readonly id: AutonomousOutcomeProfileId;
  readonly label: string;
  readonly concisePromise: string;
  readonly completionMeaning: string;
  readonly requiredTerminalSuccessCriteria: readonly string[];
  readonly requiredActionClassIds: readonly ActionClassId[];
}

export const AUTONOMOUS_OUTCOME_PROFILES: Readonly<
  Record<AutonomousOutcomeProfileId, AutonomousOutcomeProfile>
> = Object.freeze({
  assessment: Object.freeze({
    id: "assessment",
    label: "Autonomous Assessment",
    concisePromise:
      "Ti-Scale autonomously discovers, assesses, validates the evidence-backed outcomes in this contract, and reports what was established.",
    completionMeaning:
      "Completion means every signed assessment criterion was evaluated. It does not imply exploit success, a shell, user access, root access, or cleanup unless those outcomes are explicitly part of a Complete Autonomous Engagement.",
    requiredTerminalSuccessCriteria: Object.freeze([]),
    requiredActionClassIds: Object.freeze([]),
  }),
  complete_engagement: Object.freeze({
    id: "complete_engagement",
    label: "Complete Autonomous Engagement",
    concisePromise:
      "Ti-Scale must execute the reviewed evidence-matched path through exploit validation, initial access, user proof, root proof, cleanup, evaluation, and reporting.",
    completionMeaning:
      "Completion requires all six terminal proof criteria. A deferred exploit, a possible CVE, reconnaissance, or a partial shell can never satisfy the contract.",
    requiredTerminalSuccessCriteria:
      AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
    requiredActionClassIds:
      AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS,
  }),
});

export type AutonomousMaterialObjectiveRequirementId =
  | "exploit_impact"
  | "initial_access"
  | "user_access"
  | "root_access";

export interface AutonomousMaterialObjectiveRequirement {
  readonly id: AutonomousMaterialObjectiveRequirementId;
  readonly label: string;
  readonly successCriteria: readonly string[];
  readonly requiredActionClassIds: readonly ActionClassId[];
}

const EXPLOIT_IMPACT_REQUIREMENT = Object.freeze({
  id: "exploit_impact",
  label: "verified exploit impact",
  successCriteria: Object.freeze([
    AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
  ]),
  requiredActionClassIds: Object.freeze([
    "exploit_validation",
  ] as const satisfies readonly ActionClassId[]),
} as const satisfies AutonomousMaterialObjectiveRequirement);

const INITIAL_ACCESS_REQUIREMENT = Object.freeze({
  id: "initial_access",
  label: "verified initial access",
  successCriteria: Object.freeze([
    AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
    AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
    AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
  ]),
  requiredActionClassIds: Object.freeze([
    "exploit_validation",
    "command_session_execution",
    "cleanup_restoration",
  ] as const satisfies readonly ActionClassId[]),
} as const satisfies AutonomousMaterialObjectiveRequirement);

const USER_ACCESS_REQUIREMENT = Object.freeze({
  id: "user_access",
  label: "verified user access or user-flag proof",
  successCriteria: Object.freeze([
    AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
    AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
    AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION,
    AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
  ]),
  requiredActionClassIds: Object.freeze([
    "exploit_validation",
    "command_session_execution",
    "data_access_impact_validation",
    "cleanup_restoration",
  ] as const satisfies readonly ActionClassId[]),
} as const satisfies AutonomousMaterialObjectiveRequirement);

const ROOT_ACCESS_REQUIREMENT = Object.freeze({
  id: "root_access",
  label: "verified root access or root-flag proof",
  successCriteria: AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
  requiredActionClassIds:
    AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS,
} as const satisfies AutonomousMaterialObjectiveRequirement);

function objectiveClauses(objective: string): readonly string[] {
  return objective
    .normalize("NFKC")
    .toLocaleLowerCase("en-US")
    .split(/(?:[.;!?\n]+|,\s*(?:but|however)\s+|\bbut\b|\bhowever\b)/gu)
    .map((clause) => clause.trim().replace(/\s+/gu, " "))
    .filter(Boolean);
}

function explicitlyNegates(
  clause: string,
  subject: RegExp,
): boolean {
  return (
    new RegExp(
      String.raw`\b(?:do not|don't|must not|never|avoid|prohibit(?:ed)?|stop before)\b(?:\s+\S+){0,4}\s+${subject.source}`,
      "iu",
    ).test(clause)
    || new RegExp(
      String.raw`\b(?:without|no)\s+(?:an?\s+)?${subject.source}`,
      "iu",
    ).test(clause)
  );
}

const EXPLOIT_SUBJECT =
  /(?:exploit(?:ation)?|weaponization|target compromise|initial access|foothold)/u;
const USER_SUBJECT =
  /(?:user(?:\.txt|\s+(?:flag|access|shell))|non-root\s+(?:access|shell|session))/u;
const ROOT_SUBJECT =
  /(?:root(?:\.txt|\s+(?:flag|access|shell))|uid\s*(?:=|is)?\s*0|privilege escalation|escalat(?:e|ion)\s+(?:privileges?\s+)?to\s+root)/u;

function hasPositiveMaterialVerbBefore(
  clause: string,
  subject: RegExp,
): boolean {
  return new RegExp(
    String.raw`\b(?:capture|obtain|retrieve|read|prove|demonstrate|achieve|gain|establish|validate|execute|perform|run|attempt|use|compromise|escalate)\b(?:\s+\S+){0,10}\s+${subject.source}`,
    "iu",
  ).test(clause);
}

/**
 * Deterministically preserves a small, reviewed set of material execution
 * outcomes expressed in operator prose. This is intentionally not a general
 * natural-language planner: ambiguous vulnerability discovery prose remains
 * ordinary assessment scope, while explicit exploit/access/flag outcomes are
 * converted into canonical criteria whose producers and evaluators are fixed.
 */
export function autonomousMaterialObjectiveRequirements(
  objective: string,
): readonly AutonomousMaterialObjectiveRequirement[] {
  const selected = new Map<
    AutonomousMaterialObjectiveRequirementId,
    AutonomousMaterialObjectiveRequirement
  >();

  for (const clause of objectiveClauses(objective)) {
    const combinedUserRoot = (
      /\b(?:capture|obtain|retrieve|prove|demonstrate|achieve|gain|establish|validate)\b(?:\s+\S+){0,8}\s+user\s*\/\s*root(?:\s+(?:access|flags?|shells?))?\b/iu.test(clause)
      || /\buser\s+(?:and|&)\s+root\s+(?:access|flags?|shells?)\s+(?:capture|proof|validation)\b/iu.test(clause)
    );
    const root = !explicitlyNegates(clause, ROOT_SUBJECT)
      && (combinedUserRoot
        || hasPositiveMaterialVerbBefore(clause, ROOT_SUBJECT)
        || /\broot(?:\.txt|\s+flag)\s+(?:capture|proof|validation)\b/iu.test(clause));
    const user = !explicitlyNegates(clause, USER_SUBJECT)
      && (combinedUserRoot
        || hasPositiveMaterialVerbBefore(clause, USER_SUBJECT)
        || /\buser(?:\.txt|\s+flag)\s+(?:capture|proof|validation)\b/iu.test(clause));
    const initialAccess = !explicitlyNegates(clause, EXPLOIT_SUBJECT)
      && /\b(?:gain|obtain|establish|achieve|prove|demonstrate)\b(?:\s+\S+){0,8}\s+(?:initial access|foothold|interactive shell|remote shell)\b/iu.test(clause);
    const exploit = !explicitlyNegates(clause, EXPLOIT_SUBJECT)
      && (
        hasPositiveMaterialVerbBefore(clause, /(?:exploit(?:ation)?|weaponization)/u)
        || /\bexploit\b(?:\s+\S+){0,5}\s+(?:the\s+)?(?:target|host|service|application|system)\b/iu.test(clause)
      );

    if (exploit) selected.set(EXPLOIT_IMPACT_REQUIREMENT.id, EXPLOIT_IMPACT_REQUIREMENT);
    if (initialAccess) selected.set(INITIAL_ACCESS_REQUIREMENT.id, INITIAL_ACCESS_REQUIREMENT);
    if (user) selected.set(USER_ACCESS_REQUIREMENT.id, USER_ACCESS_REQUIREMENT);
    if (root) selected.set(ROOT_ACCESS_REQUIREMENT.id, ROOT_ACCESS_REQUIREMENT);
  }

  return [
    EXPLOIT_IMPACT_REQUIREMENT,
    INITIAL_ACCESS_REQUIREMENT,
    USER_ACCESS_REQUIREMENT,
    ROOT_ACCESS_REQUIREMENT,
  ].filter(({ id }) => selected.has(id));
}

export function autonomousMaterialObjectiveSuccessCriteria(
  objective: string,
): readonly string[] {
  const selected = new Set(
    autonomousMaterialObjectiveRequirements(objective).flatMap(
      ({ successCriteria }) => successCriteria,
    ),
  );
  return AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA.filter(
    (criterion) => selected.has(criterion),
  );
}

export function autonomousMaterialObjectiveActionClassIds(
  objective: string,
): readonly ActionClassId[] {
  const selected = new Set<ActionClassId>(
    autonomousMaterialObjectiveRequirements(objective).flatMap(
      ({ requiredActionClassIds }) => requiredActionClassIds,
    ),
  );
  return AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS.filter(
    (actionClassId) => selected.has(actionClassId),
  );
}

/**
 * Deterministic, inspectable classification of the promise made by one
 * Autonomous contract. Exploit validation alone remains an assessment; an
 * explicit root objective, the reviewed full-path template, or the complete
 * terminal criterion set selects the stronger contract.
 */
export function resolveAutonomousOutcomeProfile(input: Readonly<{
  explicitProfileId?: AutonomousOutcomeProfileId;
  templateId?: string;
  objective?: string;
  successCriteria?: readonly string[];
}>): AutonomousOutcomeProfile {
  if (input.explicitProfileId) {
    return AUTONOMOUS_OUTCOME_PROFILES[input.explicitProfileId];
  }
  const criteria = new Set(
    (input.successCriteria ?? []).map((criterion) =>
      criterion.trim().normalize("NFKC").replace(/\s+/gu, " ")
        .toLocaleLowerCase("en-US")),
  );
  const hasCompleteCriteria =
    AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA.every(
      (criterion) => criteria.has(
        criterion.trim().normalize("NFKC").replace(/\s+/gu, " ")
          .toLocaleLowerCase("en-US"),
      ),
    );
  const explicitRootObjective = autonomousMaterialObjectiveRequirements(
    input.objective ?? "",
  ).some(({ id }) => id === "root_access");
  return (
    input.templateId === "htb_web_full_path"
    || input.templateId === "full_authorized_lab_compromise"
    || hasCompleteCriteria
    || explicitRootObjective
  )
    ? AUTONOMOUS_OUTCOME_PROFILES.complete_engagement
    : AUTONOMOUS_OUTCOME_PROFILES.assessment;
}

/** Paired canonical JSON/Markdown outputs produced atomically for terminal Autonomous runs. */
export const AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS = Object.freeze([
  "machine_readable_export",
  "pdf_html_markdown_report",
] as const satisfies readonly DeliverableId[]);

export interface AutonomousOutcomeCapability {
  readonly actionClassId: ActionClassId;
  /** Exact normalized target kinds accepted by the mounted executor. */
  readonly targetKinds: readonly ("domain" | "ip")[];
  readonly successCriteria: readonly string[];
  readonly evidenceTypeIds: readonly EvidenceTypeId[];
  readonly deliverableIds: readonly DeliverableId[];
}

/**
 * Canonical outcome claims that a mounted Autonomous executor can prove.
 *
 * This registry deliberately contains only reviewed terminal routes. Generic
 * mission-template prose is not an executable success criterion and must not
 * be copied into a signed contract merely because it sounds appropriate.
 */
export const AUTONOMOUS_OUTCOME_CAPABILITIES: Readonly<
  Partial<Record<ActionClassId, AutonomousOutcomeCapability>>
> = Object.freeze({
  dns_domain_certificate_discovery: Object.freeze({
    actionClassId: "dns_domain_certificate_discovery",
    targetKinds: Object.freeze(["domain"] as const),
    successCriteria: Object.freeze([AUTONOMOUS_DNS_A_SUCCESS_CRITERION]),
    evidenceTypeIds: Object.freeze(["dns_certificate_record"] as const),
    // Canonical terminal reports summarize only committed evaluation,
    // evidence, findings, and provenance; they do not fabricate maps.
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  active_host_discovery: Object.freeze({
    actionClassId: "active_host_discovery",
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION]),
    evidenceTypeIds: Object.freeze(["asset_discovery_proof"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  port_service_enumeration: Object.freeze({
    actionClassId: "port_service_enumeration",
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION]),
    evidenceTypeIds: Object.freeze([
      "port_service_scan_result",
      "service_version_fingerprint",
    ] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  web_crawling_page_capture: Object.freeze({
    actionClassId: "web_crawling_page_capture",
    // The executor keeps the mission target as the exact IP and derives only
    // evidence-backed origins behind its sealed local authorization boundary.
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION]),
    evidenceTypeIds: Object.freeze(["http_exchange"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  os_technology_fingerprinting: Object.freeze({
    actionClassId: "os_technology_fingerprinting",
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION]),
    evidenceTypeIds: Object.freeze(["service_version_fingerprint"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  web_content_endpoint_discovery_fuzzing: Object.freeze({
    actionClassId: "web_content_endpoint_discovery_fuzzing",
    // Exact origins remain derived from verified Full-TCP and HTTP evidence;
    // the canonical mission target stays the single authorized IP literal.
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION]),
    evidenceTypeIds: Object.freeze(["endpoint_discovery_result"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  cve_intelligence_applicability_validation: Object.freeze({
    actionClassId: "cve_intelligence_applicability_validation",
    // The target remains the exact authorized asset. Product/version inputs
    // are derived only from verified evidence produced by an earlier step.
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION]),
    evidenceTypeIds: Object.freeze(["cve_applicability"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  vulnerability_configuration_assessment: Object.freeze({
    actionClassId: "vulnerability_configuration_assessment",
    // The mission target remains the exact authorized IP. Contactable origins
    // are re-derived from verified HTTP evidence immediately before dispatch.
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([
      AUTONOMOUS_VULNERABILITY_ASSESSMENT_SUCCESS_CRITERION,
    ]),
    evidenceTypeIds: Object.freeze(["configuration_snapshot"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  exploit_validation: Object.freeze({
    actionClassId: "exploit_validation",
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([
      AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
    ]),
    evidenceTypeIds: Object.freeze([
      "exploit_validation_result",
      "finding_reproduction",
    ] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  command_session_execution: Object.freeze({
    actionClassId: "command_session_execution",
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([
      AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
    ]),
    evidenceTypeIds: Object.freeze(["session_command_outcome"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  data_access_impact_validation: Object.freeze({
    actionClassId: "data_access_impact_validation",
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([
      AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION,
      AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
    ]),
    evidenceTypeIds: Object.freeze(["privilege_access_proof"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  privilege_escalation: Object.freeze({
    actionClassId: "privilege_escalation",
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([
      AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION,
    ]),
    evidenceTypeIds: Object.freeze(["privilege_access_proof"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
  cleanup_restoration: Object.freeze({
    actionClassId: "cleanup_restoration",
    targetKinds: Object.freeze(["ip"] as const),
    successCriteria: Object.freeze([
      AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
    ]),
    evidenceTypeIds: Object.freeze(["session_command_outcome"] as const),
    deliverableIds: AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  }),
});

export function autonomousOutcomeCapabilities(
  actionClassIds: readonly string[],
): readonly AutonomousOutcomeCapability[] {
  return actionClassIds.flatMap((actionClassId) => {
    const capability = AUTONOMOUS_OUTCOME_CAPABILITIES[actionClassId as ActionClassId];
    return capability ? [capability] : [];
  });
}

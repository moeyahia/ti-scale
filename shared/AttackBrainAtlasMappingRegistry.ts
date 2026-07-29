export const BRAIN_ATLAS_REGIONS = [
  "frontal",
  "parietal",
  "temporal",
  "occipital",
  "cerebellum",
  "stem",
] as const;

export type BrainAtlasRegion = (typeof BRAIN_ATLAS_REGIONS)[number];

export const BRAIN_ATLAS_KINDS = [
  "person",
  "concept",
  "tool",
  "source",
  "workThread",
  "decision",
  "project",
  "incident",
  "index",
] as const;

export type BrainAtlasKind = (typeof BRAIN_ATLAS_KINDS)[number];

export const OPERATOR_PROFILE_BRAIN_ATLAS_CLASSES = [
  "operator",
  "preference",
  "application_domain",
] as const;

export type OperatorProfileBrainAtlasClass =
  (typeof OPERATOR_PROFILE_BRAIN_ATLAS_CLASSES)[number];

export interface OperatorProfileBrainAtlasMapping {
  readonly profileClass: OperatorProfileBrainAtlasClass;
  readonly selector: `operator_profile_class:${OperatorProfileBrainAtlasClass}`;
  readonly nodeType: "operator" | "preference" | "entity";
  readonly requiredIdPrefix?: "mem_prefdomain_";
  readonly kind: BrainAtlasKind;
  readonly region: BrainAtlasRegion;
  readonly meaning: string;
}

/**
 * A separate, consent-bound visual classification for the explicit Operator
 * Profile projection. These entries are deliberately not part of reusable
 * attack knowledge: they cannot be retrieved as tactics, expand mission
 * scope, or admit target/asset/entity records. The only `entity` form is the
 * finite application-domain vocabulary created with the stable
 * `mem_prefdomain_` identity by OperatorPreferenceImportService.
 */
export const OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY = [
  {
    profileClass: "operator",
    selector: "operator_profile_class:operator",
    nodeType: "operator",
    kind: "person",
    region: "frontal",
    meaning: "The explicitly consented operator profile root.",
  },
  {
    profileClass: "preference",
    selector: "operator_profile_class:preference",
    nodeType: "preference",
    kind: "decision",
    region: "frontal",
    meaning: "An explicitly confirmed collaboration preference.",
  },
  {
    profileClass: "application_domain",
    selector: "operator_profile_class:application_domain",
    nodeType: "entity",
    requiredIdPrefix: "mem_prefdomain_",
    kind: "concept",
    region: "frontal",
    meaning: "A finite, target-free product surface to which an operator preference applies.",
  },
] as const satisfies readonly OperatorProfileBrainAtlasMapping[];

export function operatorProfileBrainAtlasMapping(
  node: Readonly<{ id: string; nodeType: string }>,
): OperatorProfileBrainAtlasMapping | undefined {
  return OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY.find((mapping) => (
    mapping.nodeType === node.nodeType
    && (!("requiredIdPrefix" in mapping) || node.id.startsWith(mapping.requiredIdPrefix))
  ));
}

export const ATTACK_BRAIN_ATLAS_NODE_TYPES = [
  "technology_product", "exact_version_fingerprint", "version_range_fingerprint",
  "operating_system", "kernel", "framework", "runtime", "database", "firewall",
  "waf", "proxy", "security_control", "topology_pattern", "topology_role", "cve",
  "advisory", "cwe", "misconfiguration", "attack_vector", "attack_tactic",
  "attack_technique", "attack_procedure", "procedure_version", "prerequisite",
  "attribute", "discovery_pattern", "fingerprint_pattern", "script_artifact",
  "tool_artifact", "outcome", "evidence_pattern", "validation_pattern",
  "failure_mode", "operational_hazard", "target_state_transition", "health_check",
  "recovery_pattern", "alternative", "detection", "remediation", "strategy",
  "attack_lesson", "research",
] as const;

export type AttackBrainAtlasNodeType = (typeof ATTACK_BRAIN_ATLAS_NODE_TYPES)[number];

export interface AttackBrainAtlasMapping {
  readonly nodeType: AttackBrainAtlasNodeType;
  readonly kind: BrainAtlasKind;
  readonly region: BrainAtlasRegion;
  readonly folder: string;
  readonly meaning: string;
}

/**
 * One authoritative bridge between Ti-Scale's reusable attack-memory model,
 * its Obsidian folder projection, and Brain Atlas's fixed visual vocabulary.
 * Target, mission, address, and journey records are intentionally absent.
 */
export const ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY = [
  { nodeType: "technology_product", kind: "concept", region: "parietal", folder: "20 Technology Products", meaning: "A reusable product or component identity." },
  { nodeType: "exact_version_fingerprint", kind: "concept", region: "parietal", folder: "21 Versions and Fingerprints", meaning: "Evidence that identifies one exact product version." },
  { nodeType: "version_range_fingerprint", kind: "concept", region: "parietal", folder: "21 Versions and Fingerprints", meaning: "Evidence that constrains a product to a bounded version range." },
  { nodeType: "operating_system", kind: "concept", region: "parietal", folder: "22 Software Stacks", meaning: "A reusable operating-system family or release constraint." },
  { nodeType: "kernel", kind: "concept", region: "parietal", folder: "22 Software Stacks", meaning: "A reusable kernel family or version constraint." },
  { nodeType: "framework", kind: "concept", region: "parietal", folder: "22 Software Stacks", meaning: "An application framework in a reusable technology stack." },
  { nodeType: "runtime", kind: "concept", region: "parietal", folder: "22 Software Stacks", meaning: "A language or execution runtime in a reusable technology stack." },
  { nodeType: "database", kind: "concept", region: "parietal", folder: "22 Software Stacks", meaning: "A database product or reusable database constraint." },
  { nodeType: "firewall", kind: "tool", region: "parietal", folder: "23 Security Controls", meaning: "A firewall product or behavior that changes attack applicability." },
  { nodeType: "waf", kind: "tool", region: "parietal", folder: "23 Security Controls", meaning: "A web application firewall product or behavior." },
  { nodeType: "proxy", kind: "tool", region: "parietal", folder: "23 Security Controls", meaning: "A proxy product or behavior in a reusable stack." },
  { nodeType: "security_control", kind: "tool", region: "parietal", folder: "23 Security Controls", meaning: "A reusable defensive control or enforcement boundary." },
  { nodeType: "topology_pattern", kind: "index", region: "stem", folder: "30 Topology Patterns", meaning: "An address-free network or application topology pattern." },
  { nodeType: "topology_role", kind: "index", region: "stem", folder: "30 Topology Patterns", meaning: "A reusable role within a topology, independent of target identity." },
  { nodeType: "cve", kind: "source", region: "occipital", folder: "40 Vulnerabilities and Weaknesses", meaning: "A CVE record with applicability grounded in version evidence." },
  { nodeType: "advisory", kind: "source", region: "occipital", folder: "40 Vulnerabilities and Weaknesses", meaning: "An authoritative product or vulnerability advisory." },
  { nodeType: "cwe", kind: "source", region: "occipital", folder: "40 Vulnerabilities and Weaknesses", meaning: "A reusable weakness classification." },
  { nodeType: "misconfiguration", kind: "concept", region: "occipital", folder: "40 Vulnerabilities and Weaknesses", meaning: "A reusable unsafe configuration pattern." },
  { nodeType: "attack_vector", kind: "workThread", region: "frontal", folder: "41 Attack Vectors", meaning: "The route or surface through which an attack becomes possible." },
  { nodeType: "attack_tactic", kind: "workThread", region: "frontal", folder: "42 Techniques and Procedures", meaning: "A reusable attack objective or tactic." },
  { nodeType: "attack_technique", kind: "workThread", region: "frontal", folder: "42 Techniques and Procedures", meaning: "A reusable technical method for achieving an attack objective." },
  { nodeType: "attack_procedure", kind: "workThread", region: "frontal", folder: "42 Techniques and Procedures", meaning: "An evidence-backed ordered procedure with bounded conditions." },
  { nodeType: "procedure_version", kind: "workThread", region: "cerebellum", folder: "42 Techniques and Procedures", meaning: "An immutable version of an attack procedure or execution sequence." },
  { nodeType: "prerequisite", kind: "concept", region: "stem", folder: "43 Prerequisites and Attributes", meaning: "A condition that must hold before a procedure is applicable." },
  { nodeType: "attribute", kind: "concept", region: "stem", folder: "43 Prerequisites and Attributes", meaning: "A normalized reusable property used for matching." },
  { nodeType: "discovery_pattern", kind: "source", region: "occipital", folder: "44 Discovery and Fingerprints", meaning: "A repeatable way to discover a relevant product, behavior, or surface." },
  { nodeType: "fingerprint_pattern", kind: "source", region: "occipital", folder: "44 Discovery and Fingerprints", meaning: "A repeatable pattern that identifies a product or version." },
  { nodeType: "script_artifact", kind: "tool", region: "cerebellum", folder: "45 Scripts and Tools", meaning: "A versioned reusable script with tests, risks, and provenance." },
  { nodeType: "tool_artifact", kind: "tool", region: "cerebellum", folder: "45 Scripts and Tools", meaning: "A reusable tool binding or versioned tool artifact." },
  { nodeType: "outcome", kind: "decision", region: "temporal", folder: "50 Outcomes and Validation", meaning: "A verified success, failure, partial, or safely aborted result." },
  { nodeType: "evidence_pattern", kind: "source", region: "occipital", folder: "50 Outcomes and Validation", meaning: "The evidence form required to support a reusable claim." },
  { nodeType: "validation_pattern", kind: "source", region: "occipital", folder: "50 Outcomes and Validation", meaning: "A bounded method for recognizing success or failure." },
  { nodeType: "failure_mode", kind: "incident", region: "temporal", folder: "51 Operational Hazards", meaning: "A reusable technical failure mechanism and its conditions." },
  { nodeType: "operational_hazard", kind: "incident", region: "temporal", folder: "51 Operational Hazards", meaning: "A harmful or destabilizing procedure-state combination to avoid." },
  { nodeType: "target_state_transition", kind: "incident", region: "temporal", folder: "51 Operational Hazards", meaning: "A reusable transition between observable system states." },
  { nodeType: "health_check", kind: "tool", region: "cerebellum", folder: "51 Operational Hazards", meaning: "A bounded probe proving a required system state." },
  { nodeType: "recovery_pattern", kind: "decision", region: "temporal", folder: "52 Recovery and Alternatives", meaning: "A verified recovery sequence for a known failure or hazard." },
  { nodeType: "alternative", kind: "decision", region: "temporal", folder: "52 Recovery and Alternatives", meaning: "A safer or materially different approach under stated conditions." },
  { nodeType: "detection", kind: "concept", region: "occipital", folder: "53 Detection and Remediation", meaning: "A reusable way to detect the behavior or condition." },
  { nodeType: "remediation", kind: "decision", region: "cerebellum", folder: "53 Detection and Remediation", meaning: "A verified mitigation or restoration procedure." },
  { nodeType: "strategy", kind: "project", region: "frontal", folder: "60 Strategies and Lessons", meaning: "A versioned reusable orchestration strategy." },
  { nodeType: "attack_lesson", kind: "concept", region: "temporal", folder: "60 Strategies and Lessons", meaning: "An operator-verified reusable attack or avoidance lesson." },
  { nodeType: "research", kind: "source", region: "occipital", folder: "61 Research", meaning: "A bounded research result with experiment provenance." },
] as const satisfies readonly AttackBrainAtlasMapping[];

const MAPPING_BY_NODE_TYPE = new Map<AttackBrainAtlasNodeType, AttackBrainAtlasMapping>(
  ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.map((mapping) => [mapping.nodeType, mapping]),
);

export const ATTACK_BRAIN_ATLAS_VAULT_FOLDERS = Object.freeze(
  [...new Set(ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.map((mapping) => mapping.folder))],
);

export function attackBrainAtlasMapping(
  nodeType: AttackBrainAtlasNodeType,
): AttackBrainAtlasMapping {
  const mapping = MAPPING_BY_NODE_TYPE.get(nodeType);
  if (!mapping) throw new Error(`Brain Atlas mapping is missing for reusable node type ${nodeType}`);
  return mapping;
}

export function assertAttackBrainAtlasMappingRegistryComplete(): void {
  const expected = new Set<string>(ATTACK_BRAIN_ATLAS_NODE_TYPES);
  const actual = new Set<string>();
  for (const mapping of ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY) {
    if (actual.has(mapping.nodeType)) {
      throw new Error(`Brain Atlas mapping is duplicated for reusable node type ${mapping.nodeType}`);
    }
    actual.add(mapping.nodeType);
    if (!expected.has(mapping.nodeType)) {
      throw new Error(`Brain Atlas mapping contains unknown reusable node type ${mapping.nodeType}`);
    }
    if (!mapping.folder.trim() || mapping.folder.includes("/") || mapping.folder.includes("\\")) {
      throw new Error(`Brain Atlas mapping folder is invalid for ${mapping.nodeType}`);
    }
  }
  const missing = [...expected].filter((nodeType) => !actual.has(nodeType));
  if (missing.length > 0) {
    throw new Error(`Brain Atlas mapping is missing reusable node types: ${missing.join(", ")}`);
  }
}

export function assertOperatorProfileBrainAtlasMappingRegistryComplete(): void {
  const profileClasses = new Set<string>();
  const selectors = new Set<string>();
  for (const mapping of OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY) {
    if (profileClasses.has(mapping.profileClass) || selectors.has(mapping.selector)) {
      throw new Error(`Brain Atlas Operator Profile mapping is duplicated for ${mapping.profileClass}`);
    }
    profileClasses.add(mapping.profileClass);
    selectors.add(mapping.selector);
    if (!BRAIN_ATLAS_KINDS.includes(mapping.kind) || !BRAIN_ATLAS_REGIONS.includes(mapping.region)) {
      throw new Error(`Brain Atlas Operator Profile mapping is invalid for ${mapping.profileClass}`);
    }
    if (mapping.nodeType === "entity" && mapping.requiredIdPrefix !== "mem_prefdomain_") {
      throw new Error("Brain Atlas Operator Profile entity mapping must remain bound to application-domain identities");
    }
    if (mapping.nodeType !== "entity" && "requiredIdPrefix" in mapping) {
      throw new Error(`Brain Atlas Operator Profile mapping has an unexpected identity prefix for ${mapping.profileClass}`);
    }
  }
  const expected = new Set<string>(OPERATOR_PROFILE_BRAIN_ATLAS_CLASSES);
  const missing = [...expected].filter((profileClass) => !profileClasses.has(profileClass));
  if (missing.length > 0) {
    throw new Error(`Brain Atlas Operator Profile mapping is missing classes: ${missing.join(", ")}`);
  }
}

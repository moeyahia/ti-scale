import {
  ATTACK_CENTRIC_EDGE_TYPES,
  isAttackCentricReusableNodeType,
  type AttackCentricEdgeType,
  type CreateMemoryCandidateInput,
  type CreateMemoryEdgeInput,
  type CreateMemoryNodeInput,
  type MemoryNodeType,
} from "./types";

export interface AttackKnowledgeOperationalLabel {
  readonly value: string;
  readonly category: "engagement_label" | "target_identifier";
}

type EndpointRule = Readonly<{
  sources: ReadonlySet<MemoryNodeType>;
  targets: ReadonlySet<MemoryNodeType>;
}>;

const set = (...values: readonly MemoryNodeType[]): ReadonlySet<MemoryNodeType> =>
  new Set(values);

const PRODUCT_TYPES = set(
  "technology_product", "operating_system", "kernel", "framework", "runtime",
  "database", "firewall", "waf", "proxy", "security_control",
);
const VERSION_TYPES = set("exact_version_fingerprint", "version_range_fingerprint");
const ATTACK_TYPES = set(
  "attack_tactic", "attack_vector", "attack_technique", "attack_procedure",
  "procedure_version", "strategy",
);
const CONTROL_TYPES = set("firewall", "waf", "proxy", "security_control");
const WEAKNESS_TYPES = set("cve", "advisory", "cwe", "misconfiguration");
const EXECUTION_ARTIFACT_TYPES = set("script_artifact", "tool_artifact", "tool");

/**
 * Endpoint constraints for new reusable relationship vocabulary. Legacy edge
 * types retain their existing behavior so historical graphs and APIs remain
 * readable. New applicability claims cannot be attached to arbitrary nodes.
 */
export const ATTACK_CENTRIC_EDGE_ENDPOINTS: Readonly<Record<AttackCentricEdgeType, EndpointRule>> =
  Object.freeze({
    has_exact_version: {
      sources: new Set<MemoryNodeType>([...PRODUCT_TYPES, "attack_procedure"]),
      targets: set("exact_version_fingerprint", "procedure_version"),
    },
    has_version_range: {
      sources: new Set<MemoryNodeType>([...PRODUCT_TYPES, "cve", "advisory"]),
      targets: set("version_range_fingerprint"),
    },
    version_in_range: {
      sources: set("exact_version_fingerprint"),
      targets: set("version_range_fingerprint"),
    },
    runs_on: {
      sources: new Set<MemoryNodeType>([...PRODUCT_TYPES, "tool_artifact", "script_artifact"]),
      targets: set("operating_system", "kernel"),
    },
    built_with: { sources: PRODUCT_TYPES, targets: set("framework", "runtime") },
    uses_runtime: {
      sources: set("technology_product", "framework", "script_artifact", "tool_artifact"),
      targets: set("runtime"),
    },
    uses_database: {
      sources: set("technology_product", "framework", "runtime"),
      targets: set("database"),
    },
    protected_by: {
      sources: new Set<MemoryNodeType>([...PRODUCT_TYPES, "topology_pattern"]),
      targets: CONTROL_TYPES,
    },
    has_topology_role: { sources: set("topology_pattern"), targets: set("topology_role") },
    matches_fingerprint: {
      sources: new Set<MemoryNodeType>([...PRODUCT_TYPES, ...VERSION_TYPES]),
      targets: set("fingerprint_pattern"),
    },
    discovered_by: {
      sources: new Set<MemoryNodeType>([...PRODUCT_TYPES, "topology_pattern", "topology_role"]),
      targets: set("discovery_pattern"),
    },
    fingerprinted_by: {
      sources: new Set<MemoryNodeType>([...PRODUCT_TYPES, ...VERSION_TYPES]),
      targets: set("fingerprint_pattern"),
    },
    affects: {
      sources: WEAKNESS_TYPES,
      targets: new Set<MemoryNodeType>([...PRODUCT_TYPES, ...VERSION_TYPES]),
    },
    classified_as: {
      sources: set(
        "cve", "advisory", "misconfiguration", "attack_vector", "attack_technique",
        "attack_procedure",
      ),
      targets: set("cwe", "advisory", "attribute", "attack_vector", "attack_technique"),
    },
    exploits: { sources: ATTACK_TYPES, targets: WEAKNESS_TYPES },
    requires: {
      sources: new Set<MemoryNodeType>([...ATTACK_TYPES, ...EXECUTION_ARTIFACT_TYPES]),
      targets: set("prerequisite"),
    },
    has_attribute: {
      sources: new Set<MemoryNodeType>([...PRODUCT_TYPES, ...VERSION_TYPES, ...ATTACK_TYPES, ...WEAKNESS_TYPES, "topology_pattern"]),
      targets: set("attribute"),
    },
    implemented_by: { sources: ATTACK_TYPES, targets: EXECUTION_ARTIFACT_TYPES },
    tested_against: {
      sources: new Set<MemoryNodeType>([...ATTACK_TYPES, ...EXECUTION_ARTIFACT_TYPES]),
      targets: new Set<MemoryNodeType>([...PRODUCT_TYPES, ...VERSION_TYPES, "topology_pattern"]),
    },
    produces_outcome: {
      sources: new Set<MemoryNodeType>([...ATTACK_TYPES, ...EXECUTION_ARTIFACT_TYPES]),
      targets: set("outcome"),
    },
    failed_because: { sources: set("outcome"), targets: set("failure_mode") },
    recovered_with: {
      sources: set("outcome", "failure_mode"),
      targets: set("recovery_pattern", "alternative"),
    },
    alternative_to: {
      sources: set("alternative", "recovery_pattern", "attack_technique", "attack_procedure", "strategy"),
      targets: set("alternative", "recovery_pattern", "attack_technique", "attack_procedure", "strategy"),
    },
    validated_by: {
      sources: new Set<MemoryNodeType>([...WEAKNESS_TYPES, ...VERSION_TYPES, "outcome", "discovery_pattern", "fingerprint_pattern"]),
      targets: set("evidence_pattern", "validation_pattern"),
    },
    detected_by: {
      sources: new Set<MemoryNodeType>([...ATTACK_TYPES, "misconfiguration"]),
      targets: set("detection"),
    },
    remediated_by: { sources: WEAKNESS_TYPES, targets: set("remediation") },
    applicable_to: {
      sources: new Set<MemoryNodeType>([...WEAKNESS_TYPES, ...ATTACK_TYPES]),
      targets: new Set<MemoryNodeType>([...PRODUCT_TYPES, ...VERSION_TYPES, "topology_pattern"]),
    },
    not_applicable_to: {
      sources: new Set<MemoryNodeType>([...WEAKNESS_TYPES, ...ATTACK_TYPES]),
      targets: new Set<MemoryNodeType>([...PRODUCT_TYPES, ...VERSION_TYPES, "topology_pattern"]),
    },
    mitigates: {
      sources: new Set<MemoryNodeType>([...CONTROL_TYPES, "detection", "remediation"]),
      targets: new Set<MemoryNodeType>([...WEAKNESS_TYPES, ...ATTACK_TYPES]),
    },
    bypasses: { sources: ATTACK_TYPES, targets: CONTROL_TYPES },
    improves: {
      sources: set("strategy", "attack_lesson", "research"),
      targets: new Set<MemoryNodeType>([...ATTACK_TYPES, ...EXECUTION_ARTIFACT_TYPES, "detection", "remediation"]),
    },
    caused: {
      sources: set("attack_vector", "attack_technique", "attack_procedure", "procedure_version", "script_artifact", "tool_artifact"),
      targets: set("operational_hazard", "failure_mode"),
    },
    leaves_in_state: {
      sources: set("operational_hazard", "outcome", "failure_mode"),
      targets: set("target_state_transition"),
    },
    requires_recovery: {
      sources: set("operational_hazard", "failure_mode", "target_state_transition"),
      targets: set("recovery_pattern"),
    },
    avoid_after: {
      sources: set("attack_vector", "attack_technique", "attack_procedure", "procedure_version"),
      targets: set("operational_hazard", "failure_mode", "target_state_transition"),
    },
    safe_when: {
      sources: set("attack_vector", "attack_technique", "attack_procedure", "procedure_version", "operational_hazard"),
      targets: set("health_check", "prerequisite", "attribute", "target_state_transition"),
    },
    mitigated_by: {
      sources: set("operational_hazard", "failure_mode", "target_state_transition"),
      targets: set("recovery_pattern", "alternative", "remediation", "health_check"),
    },
  });

const ATTACK_EDGE_SET: ReadonlySet<string> = new Set(ATTACK_CENTRIC_EDGE_TYPES);

export function validateAttackCentricEdgeEndpoints(
  edgeType: string,
  sourceType: MemoryNodeType,
  targetType: MemoryNodeType,
): void {
  if (!ATTACK_EDGE_SET.has(edgeType)) return;
  if (edgeType === "has_exact_version") {
    const isProductVersion = PRODUCT_TYPES.has(sourceType)
      && targetType === "exact_version_fingerprint";
    const isProcedureVersion = sourceType === "attack_procedure"
      && targetType === "procedure_version";
    if (!isProductVersion && !isProcedureVersion) {
      throw new TypeError(
        `Attack knowledge edge ${edgeType} cannot connect ${sourceType} to ${targetType}`,
      );
    }
    return;
  }
  const rule = ATTACK_CENTRIC_EDGE_ENDPOINTS[edgeType as AttackCentricEdgeType];
  if (!rule.sources.has(sourceType) || !rule.targets.has(targetType)) {
    throw new TypeError(
      `Attack knowledge edge ${edgeType} cannot connect ${sourceType} to ${targetType}`,
    );
  }
}

/** Apply the same privacy and review boundary to reusable relationships as to
 * their endpoint nodes. Canonical operational provenance remains available in
 * SQLite, but never becomes a cross-engagement semantic edge. */
export function validateAttackCentricReusableEdge(
  input: Pick<CreateMemoryEdgeInput,
    "edgeType" | "title" | "summary" | "explanation" | "scope" |
    "provenance" | "authorType" | "lifecycleStatus">,
  sourceType: MemoryNodeType,
  targetType: MemoryNodeType,
  knownOperationalLabels: readonly AttackKnowledgeOperationalLabel[] = [],
): void {
  const sourceReusable = isAttackCentricReusableNodeType(sourceType);
  const targetReusable = isAttackCentricReusableNodeType(targetType);
  if (!sourceReusable && !targetReusable) return;
  if (sourceReusable !== targetReusable) {
    throw new TypeError(
      "Reusable attack knowledge edges cannot connect to private operational memory",
    );
  }
  if (input.scope.kind !== "global" || input.scope.engagementId || input.scope.missionId) {
    throw new TypeError("Reusable attack knowledge edges must use a global scope without operational identifiers");
  }
  if (input.authorType !== "operator" && input.lifecycleStatus !== "candidate") {
    throw new TypeError("Non-operator attack knowledge edges must remain candidates");
  }
  if (input.provenance.sources.some((source) => Boolean(source.excerptRedacted))) {
    throw new TypeError("Reusable attack knowledge edges must link private provenance without source excerpts");
  }
  const unsafe = [input.title, input.summary, input.explanation]
    .flatMap((value) => [
      ...attackKnowledgeOperationalLocatorCategories(value),
      ...attackKnowledgeKnownOperationalLabelCategories(value, knownOperationalLabels),
    ]);
  if (unsafe.length > 0) {
    throw new TypeError(
      `Reusable attack knowledge edge contains private operational locators: ${[...new Set(unsafe)].sort().join(", ")}`,
    );
  }
}

const IPV4_OR_CIDR = /(?:^|[^\d])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:\/\d{1,2})?(?:$|[^\d])/u;
const IPV6 = /(?:^|[\s[(])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?:$|[\s\])},.;])/u;
const NETWORK_URL = /\b(?:https?|ssh|smb|ldap|ldaps|rdp):\/\/[^\s]+/iu;
// Reusable procedures reference artifact IDs or explicit placeholders, never a
// concrete host path. A single absolute segment such as /usr or /dev is still
// a locator; explicit placeholders such as /<workspace>/script.py and
// /${WORKSPACE}/script.py remain permitted.
const RAW_POSIX_PATH = /(?:^|[\s'"`(])\/(?!(?:<|\{\{|\$\{))[A-Za-z0-9._@%+=:,\-]+(?:\/[A-Za-z0-9._@%+=:,\-]+)*(?=$|[\s'"`),;])/u;
const RAW_WINDOWS_PATH = /(?:^|[\s'"`(])(?:[A-Za-z]:\\|\\\\)[^\s'"`]+/u;
const SCOPED_BARE_HOSTNAME = /\b(?=[A-Za-z0-9.-]{1,253}\b)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:htb|internal|local|lan|corp|home\.arpa|invalid|test)\b/iu;
const EMAIL_IDENTITY = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/iu;
const CANONICAL_OPERATIONAL_ID = /\b(?:mission|run|step|action|assignment|evidence|artifact|finding|target|asset)_[A-Za-z0-9._:-]+\b/u;
const OPAQUE_REUSABLE_NODE_ID = /^mem_(?:[0-9a-f]{32,64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/iu;

export function attackKnowledgeOperationalLocatorCategories(
  value: string,
): readonly string[] {
  const categories: string[] = [];
  if (IPV4_OR_CIDR.test(value)) categories.push("network_address");
  if (IPV6.test(value)) categories.push("network_address");
  if (NETWORK_URL.test(value)) categories.push("target_url");
  if (RAW_POSIX_PATH.test(value) || RAW_WINDOWS_PATH.test(value)) categories.push("filesystem_path");
  if (SCOPED_BARE_HOSTNAME.test(value)) categories.push("scoped_hostname");
  if (EMAIL_IDENTITY.test(value)) categories.push("email_identity");
  if (CANONICAL_OPERATIONAL_ID.test(value)) categories.push("operational_record_id");
  return [...new Set(categories)].sort();
}

function normalizedOperationalLabel(value: string): string {
  return value.normalize("NFKC").trim().toLocaleLowerCase("en-US");
}

function containsKnownOperationalLabel(value: string, label: string): boolean {
  const normalizedValue = normalizedOperationalLabel(value);
  const normalizedLabel = normalizedOperationalLabel(label);
  if (normalizedLabel.length < 5) return false;
  let offset = normalizedValue.indexOf(normalizedLabel);
  while (offset >= 0) {
    const before = offset === 0 ? "" : normalizedValue[offset - 1] ?? "";
    const afterOffset = offset + normalizedLabel.length;
    const after = afterOffset >= normalizedValue.length ? "" : normalizedValue[afterOffset] ?? "";
    const boundary = (character: string): boolean => !character || !/[\p{L}\p{N}_]/u.test(character);
    if (boundary(before) && boundary(after)) return true;
    offset = normalizedValue.indexOf(normalizedLabel, offset + 1);
  }
  return false;
}

export function attackKnowledgeKnownOperationalLabelCategories(
  value: string,
  labels: readonly AttackKnowledgeOperationalLabel[],
): readonly string[] {
  return [...new Set(labels
    .filter((label) => containsKnownOperationalLabel(value, label.value))
    .map((label) => label.category))].sort();
}

export function assertOpaqueAttackKnowledgeNodeId(
  id: string,
  nodeType: MemoryNodeType,
): void {
  if (!isAttackCentricReusableNodeType(nodeType)) return;
  if (!OPAQUE_REUSABLE_NODE_ID.test(id)) {
    throw new TypeError(
      "Reusable attack knowledge IDs must be opaque generated memory IDs",
    );
  }
}

export function reusableMemoryEdgeBoundaryIsSafe(
  sourceType: MemoryNodeType,
  targetType: MemoryNodeType,
): boolean {
  return isAttackCentricReusableNodeType(sourceType)
    === isAttackCentricReusableNodeType(targetType);
}

/**
 * Reusable attack knowledge is generalized and globally scoped. Raw mission
 * excerpts and locators remain private in memory_sources/evidence and are
 * projected only as opaque provenance references.
 */
export function validateAttackCentricReusableNode(
  input: Pick<CreateMemoryNodeInput,
    "id" | "nodeType" | "title" | "summary" | "body" | "scope" | "provenance" |
    "authorType" | "lifecycleStatus" | "confirmationState">,
  knownOperationalLabels: readonly AttackKnowledgeOperationalLabel[] = [],
): void {
  if (!isAttackCentricReusableNodeType(input.nodeType)) return;
  if (input.id) assertOpaqueAttackKnowledgeNodeId(input.id, input.nodeType);
  if (input.scope.kind !== "global" || input.scope.engagementId || input.scope.missionId) {
    throw new TypeError("Reusable attack knowledge must use a global scope without operational identifiers");
  }
  if (
    input.authorType !== "operator"
    && (input.lifecycleStatus !== "candidate" || input.confirmationState !== "pending")
  ) {
    throw new TypeError("Non-operator attack knowledge must remain a pending candidate");
  }
  if (input.provenance.sources.some((source) => Boolean(source.excerptRedacted))) {
    throw new TypeError("Reusable attack knowledge must link private provenance without source excerpts");
  }
  const unsafe = [input.title, input.summary, input.body ?? ""]
    .flatMap((value) => [
      ...attackKnowledgeOperationalLocatorCategories(value),
      ...attackKnowledgeKnownOperationalLabelCategories(value, knownOperationalLabels),
    ]);
  if (unsafe.length > 0) {
    throw new TypeError(
      `Reusable attack knowledge contains private operational locators: ${[...new Set(unsafe)].sort().join(", ")}`,
    );
  }
}

/** Candidate-stage enforcement for compiler/import paths. Confirmation runs
 * the stricter node validator again, but unsafe operational text must never be
 * persisted in the reusable-candidate inbox in the first place. */
export function validateAttackCentricReusableCandidate(
  input: Pick<CreateMemoryCandidateInput,
    "nodeType" | "title" | "summary" | "body" | "scope" | "provenance">,
  knownOperationalLabels: readonly AttackKnowledgeOperationalLabel[] = [],
): void {
  if (!isAttackCentricReusableNodeType(input.nodeType)) return;
  if (input.scope.kind !== "global" || input.scope.engagementId || input.scope.missionId) {
    throw new TypeError("Reusable attack knowledge candidates must use a global scope without operational identifiers");
  }
  if (input.provenance.sources.some((source) => Boolean(source.excerptRedacted))) {
    throw new TypeError("Reusable attack knowledge candidates must link private provenance without source excerpts");
  }
  const unsafe = [input.title, input.summary, input.body ?? ""]
    .flatMap((value) => [
      ...attackKnowledgeOperationalLocatorCategories(value),
      ...attackKnowledgeKnownOperationalLabelCategories(value, knownOperationalLabels),
    ]);
  if (unsafe.length > 0) {
    throw new TypeError(
      `Reusable attack knowledge candidate contains private operational locators: ${[...new Set(unsafe)].sort().join(", ")}`,
    );
  }
}

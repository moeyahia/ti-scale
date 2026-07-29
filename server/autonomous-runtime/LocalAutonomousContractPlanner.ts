import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { RuntimeProjectionInput } from "../app/RuntimeProjectionService";
import type { SqliteDatabase } from "../db";
import {
  ACTION_CLASS_DEFINITIONS,
  buildRuntimeCapabilityProjection,
  isActionClassId,
  isEvidenceTypeId,
  isSpecialistMcpExecutionPolicy,
  type ActionClassDefinition,
  type ActionClassId,
  type EvidenceTypeId,
} from "../domain";
import { hashCanonical } from "../missions/canonical";
import { REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION } from "../orchestration";
import type {
  MissionPlanDraft,
  MissionPlannerInput,
  MissionPlannerPort,
} from "../command-runtime";
// Import the runtime error class from its defining module. Importing the
// command-runtime barrel here creates a circular module edge through the
// composition root under Bun and can produce a second class identity, which
// would make the runtime erase the planner's precise safe-stop code.
import { CommandRuntimeError } from "../command-runtime/types";
import { productAgentIdForActionClass } from "../agents";
import {
  LOCAL_AUTONOMOUS_PLANNER_BOUNDARY_SCHEMA_VERSION,
  LOCAL_AUTONOMOUS_PLANNING_POLICY_SCHEMA_VERSION,
  LOCAL_AUTONOMOUS_TARGET_KINDS,
  type LocalAutonomousActionBinding,
  type LocalAutonomousMcpActionBinding,
  type LocalAutonomousPlannerBoundary,
  type LocalAutonomousPlanningPolicy,
  type LocalAutonomousProcessActionBinding,
  type LocalAutonomousTargetKind,
} from "./types";
import {
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
} from "./AutonomousCveApplicability";
import {
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
} from "./AutonomousVulnerabilityAssessment";
import {
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
} from "./AutonomousExploitValidationEligibility";
import {
  AUTONOMOUS_LINUX_FLAG_ACTION_CLASS,
  AUTONOMOUS_LINUX_SESSION_ACTION_CLASS,
  AUTONOMOUS_LINUX_SESSION_IDENTITY_ACTION_TYPE,
  AUTONOMOUS_LINUX_USER_FLAG_PROOF_ACTION_TYPE,
} from "./AutonomousLinuxPostExploitSession";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS,
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_CLASS,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
} from "./CandidateLinuxPrivilegeContinuation";
import type {
  AutonomousExploitValidationPlanningPort,
  AutonomousExploitValidationPlanningReadiness,
} from "./AutonomousExploitValidationPlanning";

export const LOCAL_AUTONOMOUS_PLANNER_ID =
  "ti-scale.local-autonomous-contract-planner.v1";
export const LOCAL_AUTONOMOUS_PLANNER_CONTRACT_SCHEMA_VERSION =
  "ti-scale.autonomous-planner-adapter.v1" as const;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const PARAMETER_KEY = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SECRET_KEY = /(?:^|[_-])(api[_-]?key|auth|authorization|bearer|credential|password|private[_-]?key|secret|session|token)(?:$|[_-])/iu;
const MAXIMUM_STATIC_PARAMETER_BYTES = 64 * 1_024;
const RECOVERY_PLANNING_MEMORY_TYPES = new Set([
  "lesson",
  "attack_lesson",
  "failure",
  "failure_mode",
  "recovery",
  "recovery_pattern",
  "operational_hazard",
  "health_check",
  "alternative",
  "outcome",
]);
const CAPABILITY_PLANNING_MEMORY_TYPES = new Set([
  "tool",
  "tool_artifact",
  "mcp_capability",
]);
const ATTACK_CORPUS_PLANNING_MEMORY_TYPES = new Set([
  "technology_product",
  "exact_version_fingerprint",
  "version_range_fingerprint",
  "operating_system",
  "kernel",
  "framework",
  "runtime",
  "database",
  "firewall",
  "waf",
  "proxy",
  "security_control",
  "topology_pattern",
  "topology_role",
  "cve",
  "advisory",
  "misconfiguration",
  "attack_vector",
  "technique",
  "procedure",
  "attack_technique",
  "attack_procedure",
  "procedure_version",
  "prerequisite",
  "attribute",
  "discovery_pattern",
  "fingerprint_pattern",
  "script_artifact",
]);
const RECOVERY_MEMORY_SUCCESS_CRITERION =
  "Before any retry, preserve the attributable result and require materially new evidence or a verified recovery condition; do not repeat identical work without progress.";
const CAPABILITY_MEMORY_SUCCESS_CRITERION =
  "The result must identify the reviewed specialist and exact execution binding actually used; live runtime manifests remain authoritative.";
const ATTACK_CORPUS_MEMORY_SUCCESS_CRITERION =
  "Before considering any historical technique, match the current target using evidence-backed product/version and prerequisite observations; historical outcomes remain hypotheses, never proof or authority.";
const ACTION_CLASSES = new Map<ActionClassId, ActionClassDefinition>(
  ACTION_CLASS_DEFINITIONS.map((definition) => [definition.id, definition]),
);
const AUTONOMOUS_LINUX_POST_EXPLOIT_EXACT_PROCESS_BINDINGS = Object.freeze([
  Object.freeze({
    actionClassId: AUTONOMOUS_LINUX_SESSION_ACTION_CLASS,
    toolId: AUTONOMOUS_LINUX_SESSION_IDENTITY_ACTION_TYPE,
  }),
  Object.freeze({
    actionClassId: AUTONOMOUS_LINUX_FLAG_ACTION_CLASS,
    toolId: AUTONOMOUS_LINUX_USER_FLAG_PROOF_ACTION_TYPE,
  }),
  Object.freeze({
    actionClassId: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS,
    toolId: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  }),
  Object.freeze({
    actionClassId: AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_CLASS,
    toolId: AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
  }),
  Object.freeze({
    actionClassId: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS,
    toolId: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  }),
] as const);
const AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES = Object.freeze([
  AUTONOMOUS_LINUX_SESSION_ACTION_CLASS,
  AUTONOMOUS_LINUX_FLAG_ACTION_CLASS,
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS,
] as const);
const AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS = new Set<string>(
  AUTONOMOUS_LINUX_POST_EXPLOIT_EXACT_PROCESS_BINDINGS.map(
    ({ toolId }) => toolId,
  ),
);

function isLocalProcessBinding(
  binding: LocalAutonomousActionBinding,
): binding is LocalAutonomousProcessActionBinding {
  return "executionBinding" in binding
    && binding.executionBinding === "reviewed_local_process";
}

function isMcpBinding(
  binding: LocalAutonomousActionBinding,
): binding is LocalAutonomousMcpActionBinding {
  return !isLocalProcessBinding(binding);
}

interface CanonicalContractRow {
  readonly mission_id: string;
  readonly journey: string;
  readonly contract_id: string | null;
  readonly contract_version_bound: number | null;
  readonly contract_hash_bound: string | null;
  readonly version: number;
  readonly state: string;
  readonly contract_hash: string;
  readonly action_policy_json: string;
  readonly budgets_json: string;
}

interface CanonicalActionPolicy {
  readonly allowedActionClasses: readonly ActionClassId[];
  readonly prohibitedActionClasses: readonly string[];
  readonly destructivePolicy: "prohibited" | "validate_without_executing" | "bounded_lab_only";
  readonly boundedDestructiveTargets: readonly string[];
  readonly specialistAgentIds: readonly string[];
}

interface PlanningMemoryInfluence {
  readonly citations: NonNullable<MissionPlanDraft["planningAttribution"]>["citations"];
  readonly successCriteria: readonly string[];
  readonly rationale: string;
}

/**
 * Local memory is untrusted reference data, never executable instruction.
 * Only a node's canonical type can activate one of these fixed, reviewed plan
 * guards. Titles and summaries are deliberately not interpreted, copied into
 * commands, or allowed to expand scope/tool authority.
 */
function planningMemoryInfluence(
  context: MissionPlannerInput["brainContext"],
): PlanningMemoryInfluence {
  const recoveryNodeIds = new Set<string>();
  const capabilityNodeIds = new Set<string>();
  const attackCorpusNodeIds = new Set<string>();
  for (const item of context.items) {
    if (RECOVERY_PLANNING_MEMORY_TYPES.has(item.nodeType)) {
      recoveryNodeIds.add(item.nodeId);
    } else if (CAPABILITY_PLANNING_MEMORY_TYPES.has(item.nodeType)) {
      capabilityNodeIds.add(item.nodeId);
    } else if (ATTACK_CORPUS_PLANNING_MEMORY_TYPES.has(item.nodeType)) {
      attackCorpusNodeIds.add(item.nodeId);
    }
  }
  const citations: PlanningMemoryInfluence["citations"] = [
    ...[...recoveryNodeIds].map((nodeId) => ({
      nodeId,
      influence: "Added the reviewed evidence-before-retry and no-progress guard; this memory did not grant scope or tool authority.",
    })),
    ...[...capabilityNodeIds].map((nodeId) => ({
      nodeId,
      influence: "Added attributable specialist/execution-binding validation; the live capability manifest remained authoritative.",
    })),
    ...[...attackCorpusNodeIds].map((nodeId) => ({
      nodeId,
      influence: "Added the reviewed current product/version/prerequisite corroboration guard; historical outcomes remained hypotheses and granted no authority.",
    })),
  ];
  const successCriteria = [
    ...(recoveryNodeIds.size > 0 ? [RECOVERY_MEMORY_SUCCESS_CRITERION] : []),
    ...(capabilityNodeIds.size > 0 ? [CAPABILITY_MEMORY_SUCCESS_CRITERION] : []),
    ...(attackCorpusNodeIds.size > 0 ? [ATTACK_CORPUS_MEMORY_SUCCESS_CRITERION] : []),
  ];
  const influencedClasses = [
    ...(recoveryNodeIds.size > 0 ? [`${recoveryNodeIds.size} recovery/lesson ${recoveryNodeIds.size === 1 ? "memory" : "memories"}`] : []),
    ...(capabilityNodeIds.size > 0 ? [`${capabilityNodeIds.size} capability ${capabilityNodeIds.size === 1 ? "memory" : "memories"}`] : []),
    ...(attackCorpusNodeIds.size > 0 ? [`${attackCorpusNodeIds.size} attack-corpus ${attackCorpusNodeIds.size === 1 ? "memory" : "memories"}`] : []),
  ];
  return {
    citations,
    successCriteria,
    rationale: influencedClasses.length > 0
      ? `${influencedClasses.join(" and ")} added fixed evidence, retry, and attribution guards without changing authority`
      : "no retrieved memory changed the deterministic plan",
  };
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function safeText(value: unknown, label: string, maximum = 4_000): string {
  if (typeof value !== "string" || !value.trim() || value.trim().length > maximum) {
    throw new TypeError(`${label} is invalid`);
  }
  return value.trim();
}

function safeId(value: unknown, label: string): string {
  const normalized = safeText(value, label, 200);
  if (!PUBLIC_ID.test(normalized)) throw new TypeError(`${label} is invalid`);
  return normalized;
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  const items = value.map((item, index) => safeText(item, `${label}[${index}]`, 1_000));
  if (new Set(items).size !== items.length) throw new TypeError(`${label} contains duplicates`);
  return items;
}

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertJsonSafe(value: unknown, path: string, depth = 0): void {
  if (depth > 12) throw new TypeError(`${path} exceeds the maximum JSON depth`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${path} contains a non-finite number`);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 500) throw new TypeError(`${path} contains too many values`);
    value.forEach((item, index) => assertJsonSafe(item, `${path}[${index}]`, depth + 1));
    return;
  }
  if (!plainRecord(value)) throw new TypeError(`${path} is not a plain JSON object`);
  for (const [key, item] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) throw new TypeError(`${path}.${key} looks secret-bearing`);
    assertJsonSafe(item, `${path}.${key}`, depth + 1);
  }
}

function frozenJsonRecord(
  value: Readonly<Record<string, unknown>>,
  path: string,
): Readonly<Record<string, unknown>> {
  assertJsonSafe(value, path);
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized, "utf8") > MAXIMUM_STATIC_PARAMETER_BYTES) {
    throw new RangeError(`${path} exceeds ${MAXIMUM_STATIC_PARAMETER_BYTES} bytes`);
  }
  return Object.freeze(JSON.parse(serialized) as Record<string, unknown>);
}

function expectedRisk(definition: ActionClassDefinition): LocalAutonomousActionBinding["riskClass"] {
  return definition.riskBand === "moderate" ? "medium" : definition.riskBand;
}

function validateBinding(
  value: LocalAutonomousActionBinding,
  index: number,
): LocalAutonomousActionBinding {
  if (!plainRecord(value)) throw new TypeError(`bindings[${index}] must be an object`);
  const commonExpected = [
    "actionClassId", "agentId", "bindingId", "capabilityIds", "destructive",
    "explanation", "idempotent", "modelConfigurationHash",
    "modelId", "objective", "phase", "providerId", "rationale",
    "requiredEvidenceTypeIds", "reversibility", "riskClass", "staticParameters",
    "successCriteria", "targetKinds", "targetParameter", "title",
  ];
  const localProcess = isLocalProcessBinding(value);
  const expected = localProcess
    ? [...commonExpected, "executionBinding", "toolId"]
    : [...commonExpected, "mcpServerId", "toolName"];
  if (!exactKeys(value, expected)) {
    throw new TypeError(`bindings[${index}] must contain only the exact planning-policy fields`);
  }
  if (!isActionClassId(value.actionClassId)) {
    throw new TypeError(`bindings[${index}].actionClassId is not registered`);
  }
  const definition = ACTION_CLASSES.get(value.actionClassId)!;
  const targetKinds = stringArray(value.targetKinds, `bindings[${index}].targetKinds`);
  if (
    targetKinds.length === 0
    || targetKinds.some((kind) => !LOCAL_AUTONOMOUS_TARGET_KINDS.includes(kind as LocalAutonomousTargetKind))
  ) throw new TypeError(`bindings[${index}].targetKinds is invalid`);
  const capabilityIds = stringArray(value.capabilityIds, `bindings[${index}].capabilityIds`)
    .map((id) => safeId(id, `bindings[${index}].capabilityIds`));
  if (capabilityIds.length === 0) throw new TypeError(`bindings[${index}] requires a capability`);
  const evidenceIds = stringArray(
    value.requiredEvidenceTypeIds,
    `bindings[${index}].requiredEvidenceTypeIds`,
  );
  if (evidenceIds.length === 0 || evidenceIds.some((id) => !isEvidenceTypeId(id))) {
    throw new TypeError(`bindings[${index}].requiredEvidenceTypeIds is invalid`);
  }
  if (value.riskClass !== expectedRisk(definition)) {
    throw new TypeError(`bindings[${index}].riskClass does not match the canonical registry`);
  }
  if (value.destructive !== definition.destructiveOrDisruptive) {
    throw new TypeError(`bindings[${index}].destructive does not match the canonical registry`);
  }
  if (typeof value.idempotent !== "boolean") {
    throw new TypeError(`bindings[${index}].idempotent must be boolean`);
  }
  const modelConfigurationHash = safeText(
    value.modelConfigurationHash,
    `bindings[${index}].modelConfigurationHash`,
    64,
  );
  if (!SHA256.test(modelConfigurationHash)) {
    throw new TypeError(`bindings[${index}].modelConfigurationHash must be SHA-256`);
  }
  const targetParameter = safeText(value.targetParameter, `bindings[${index}].targetParameter`, 128);
  if (!PARAMETER_KEY.test(targetParameter) || SECRET_KEY.test(targetParameter)) {
    throw new TypeError(`bindings[${index}].targetParameter is unsafe`);
  }
  const staticParameters = frozenJsonRecord(
    value.staticParameters,
    `bindings[${index}].staticParameters`,
  );
  if (Object.prototype.hasOwnProperty.call(staticParameters, targetParameter)) {
    throw new TypeError(`bindings[${index}].staticParameters shadows the target parameter`);
  }
  const successCriteria = stringArray(
    value.successCriteria,
    `bindings[${index}].successCriteria`,
  );
  if (successCriteria.length === 0) throw new TypeError(`bindings[${index}] requires success criteria`);
  const common = {
    bindingId: safeId(value.bindingId, `bindings[${index}].bindingId`),
    actionClassId: value.actionClassId,
    targetKinds: Object.freeze(targetKinds as LocalAutonomousTargetKind[]),
    phase: safeText(value.phase, `bindings[${index}].phase`, 120),
    title: safeText(value.title, `bindings[${index}].title`, 240),
    objective: safeText(value.objective, `bindings[${index}].objective`),
    explanation: safeText(value.explanation, `bindings[${index}].explanation`),
    rationale: safeText(value.rationale, `bindings[${index}].rationale`),
    successCriteria: Object.freeze(successCriteria),
    reversibility: safeText(value.reversibility, `bindings[${index}].reversibility`),
    riskClass: value.riskClass,
    idempotent: value.idempotent,
    destructive: value.destructive,
    agentId: safeId(value.agentId, `bindings[${index}].agentId`),
    providerId: safeId(value.providerId, `bindings[${index}].providerId`),
    modelId: safeId(value.modelId, `bindings[${index}].modelId`),
    modelConfigurationHash,
    targetParameter,
    staticParameters,
    capabilityIds: Object.freeze(capabilityIds),
    requiredEvidenceTypeIds: Object.freeze(evidenceIds as EvidenceTypeId[]),
  };
  return localProcess
    ? Object.freeze({
        ...common,
        executionBinding: "reviewed_local_process" as const,
        toolId: safeId(value.toolId, `bindings[${index}].toolId`),
      })
    : Object.freeze({
        ...common,
        mcpServerId: safeId(value.mcpServerId, `bindings[${index}].mcpServerId`),
        toolName: safeId(value.toolName, `bindings[${index}].toolName`),
      });
}

export function validateLocalAutonomousPlanningPolicy(
  value: LocalAutonomousPlanningPolicy,
): LocalAutonomousPlanningPolicy {
  if (!plainRecord(value) || !exactKeys(value, ["bindings", "maximumSteps", "policyId", "schemaVersion"])) {
    throw new TypeError("Local Autonomous planning policy has unexpected fields");
  }
  if (value.schemaVersion !== LOCAL_AUTONOMOUS_PLANNING_POLICY_SCHEMA_VERSION) {
    throw new TypeError("Local Autonomous planning policy schema is unsupported");
  }
  const policyId = safeId(value.policyId, "planning policy ID");
  if (!Number.isSafeInteger(value.maximumSteps) || value.maximumSteps < 1 || value.maximumSteps > 32) {
    throw new RangeError("Local Autonomous maximumSteps must be 1 through 32");
  }
  if (!Array.isArray(value.bindings) || value.bindings.length === 0 || value.bindings.length > 128) {
    throw new RangeError("Local Autonomous bindings must contain 1 through 128 records");
  }
  const bindings = value.bindings.map(validateBinding);
  const bindingIds = bindings.map(({ bindingId }) => bindingId);
  if (new Set(bindingIds).size !== bindingIds.length) throw new TypeError("Planning binding IDs must be unique");
  const classTargetKinds = new Set<string>();
  for (const binding of bindings) {
    for (const targetKind of binding.targetKinds) {
      const key = `${binding.actionClassId}\u0000${targetKind}`;
      if (classTargetKinds.has(key)) {
        throw new TypeError(
          `Planning bindings are ambiguous for ${binding.actionClassId}/${targetKind}`,
        );
      }
      classTargetKinds.add(key);
    }
  }
  return Object.freeze({
    schemaVersion: LOCAL_AUTONOMOUS_PLANNING_POLICY_SCHEMA_VERSION,
    policyId,
    maximumSteps: value.maximumSteps,
    bindings: Object.freeze(bindings),
  });
}

function classifyTarget(value: string): LocalAutonomousTargetKind {
  const target = value.trim();
  if (/^https?:\/\//iu.test(target)) return "url";
  if (/^(?:aws|azure|gcp|cloud|subscription|project|account):/iu.test(target)) return "cloud";
  const cidr = target.match(/^(.+)\/(\d{1,3})$/u);
  if (cidr && isIP(cidr[1] ?? "") !== 0) return "cidr";
  if (isIP(target) !== 0) return "ip";
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/iu.test(target)) return "domain";
  return "environment";
}

const AUTONOMOUS_IP_RECON_ACTION_CLASSES = Object.freeze([
  "active_host_discovery",
  "port_service_enumeration",
] as const);
const AUTONOMOUS_IP_RECON_EXACT_PROCESS_BINDINGS = Object.freeze([{
  actionClassId: "active_host_discovery",
  toolId: "kali:ping-host-liveness",
}, {
  actionClassId: "port_service_enumeration",
  toolId: "kali:nmap-tcp-connect-service-scan",
}] as const);
const AUTONOMOUS_WEB_SURFACE_ACTION_CLASSES = Object.freeze([
  "web_crawling_page_capture",
  "os_technology_fingerprinting",
] as const);
const AUTONOMOUS_WEB_SURFACE_EXACT_PROCESS_BINDINGS = Object.freeze([{
  actionClassId: "web_crawling_page_capture",
  toolId: "ti-scale:autonomous-http-metadata-baseline",
}, {
  actionClassId: "os_technology_fingerprinting",
  toolId: "ti-scale:autonomous-whatweb-fingerprint",
}] as const);
const AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS =
  "web_content_endpoint_discovery_fuzzing" as const;
const AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE =
  "ti-scale:autonomous-endpoint-discovery" as const;
const AUTONOMOUS_FULL_TCP_COMPOSITE_TOOL_ID = "ti-scale:autonomous-full-tcp-baseline" as const;
const AUTONOMOUS_DEPENDENCY_TOOL_ORDER = Object.freeze([
  "kali:host-dns-query",
  "kali:ping-host-liveness",
  AUTONOMOUS_FULL_TCP_COMPOSITE_TOOL_ID,
  "ti-scale:autonomous-http-metadata-baseline",
  "ti-scale:autonomous-whatweb-fingerprint",
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
] as const);

/** Stable dependency order used when the complete verified web continuation is selected. */
export function orderLocalAutonomousBindingsForDependencies(
  bindings: readonly LocalAutonomousActionBinding[],
): readonly LocalAutonomousActionBinding[] {
  return Object.freeze(bindings
    .map((binding, index) => ({ binding, index }))
    .sort((left, right) => {
      const leftTool = isLocalProcessBinding(left.binding) ? left.binding.toolId : "";
      const rightTool = isLocalProcessBinding(right.binding) ? right.binding.toolId : "";
      const leftRank = AUTONOMOUS_DEPENDENCY_TOOL_ORDER.indexOf(
        leftTool as (typeof AUTONOMOUS_DEPENDENCY_TOOL_ORDER)[number],
      );
      const rightRank = AUTONOMOUS_DEPENDENCY_TOOL_ORDER.indexOf(
        rightTool as (typeof AUTONOMOUS_DEPENDENCY_TOOL_ORDER)[number],
      );
      return (leftRank < 0 ? Number.MAX_SAFE_INTEGER : leftRank)
        - (rightRank < 0 ? Number.MAX_SAFE_INTEGER : rightRank)
        || left.index - right.index;
    })
    .map(({ binding }) => binding));
}

function exactAutonomousIpReconTarget(value: string): boolean {
  const target = value.trim().normalize("NFKC");
  if (!target || target !== value || target.length > 253
    || /[\u0000-\u0020\u007F]/u.test(target)) return false;
  if (isIP(target) !== 0) return true;
  const host = target.endsWith(".") ? target.slice(0, -1) : target;
  return Boolean(host) && host.split(".").every((label) =>
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(label));
}

function parseObject(value: string, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!plainRecord(parsed)) throw new Error("not an object");
    return parsed;
  } catch {
    throw new CommandRuntimeError(409, "autonomous_local_contract_malformed", `${label} is malformed`, {
      humanMessage: `Safe-stopped: the signed Autonomous ${label} is malformed.`,
      retryable: false,
      category: "policy_denied",
      remediation: "Create a versioned contract amendment; do not bypass or reinterpret the stored policy.",
    });
  }
}

function policyStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) {
    throw new CommandRuntimeError(409, "autonomous_local_contract_malformed", `${label} is malformed`, {
      humanMessage: `Safe-stopped: the signed Autonomous ${label} is not an exact list.`,
      retryable: false,
      category: "policy_denied",
      remediation: "Create a versioned contract amendment with explicit registry-backed values.",
    });
  }
  return [...new Set(value.map((item) => typeof item === "string" ? item.trim() : "").filter(Boolean))];
}

function contractError(
  code: string,
  humanMessage: string,
  remediation: string,
  category: "policy_denied" | "scope_conflict" | "dependency_missing" | "invalid_input" = "policy_denied",
): CommandRuntimeError {
  return new CommandRuntimeError(409, code, humanMessage, {
    humanMessage: `Safe-stopped: ${humanMessage}`,
    retryable: false,
    category,
    remediation,
  });
}

function canonicalPolicy(row: CanonicalContractRow): CanonicalActionPolicy {
  const policy = parseObject(row.action_policy_json, "action policy");
  const allowedRaw = policyStringArray(policy.allowedActionClasses, "allowed action classes")
    .map((value) => value.toLocaleLowerCase("en-US"));
  const unsupported = allowedRaw.filter((value) => !isActionClassId(value));
  if (unsupported.length > 0) {
    throw contractError(
      "autonomous_local_action_class_unsupported",
      `the signed contract contains unsupported action classes: ${unsupported.join(", ")}.`,
      "Remove unsupported classes or install and attest their exact runtime mappings before a new run.",
      "dependency_missing",
    );
  }
  const prohibited = policyStringArray(
    policy.prohibitedActionClasses,
    "prohibited action classes",
  ).map((value) => value.toLocaleLowerCase("en-US"));
  if (allowedRaw.length === 0 || allowedRaw.some((value) => prohibited.includes(value))) {
    throw contractError(
      "autonomous_local_action_policy_ambiguous",
      "the signed action policy is empty or contradictory.",
      "Resolve every selected action class to one non-conflicting contract state.",
    );
  }
  const destructivePolicy = policy.destructivePolicy;
  if (![
    "prohibited",
    "validate_without_executing",
    "bounded_lab_only",
  ].includes(String(destructivePolicy))) {
    throw contractError(
      "autonomous_local_destructive_policy_invalid",
      "the destructive-action policy is missing or invalid.",
      "Select an explicit supported destructive-action policy in a versioned contract.",
    );
  }
  const specialists = policyStringArray(policy.specialistAgentIds, "specialist agent pool");
  if (specialists.length === 0) {
    throw contractError(
      "autonomous_local_specialist_pool_missing",
      "the signed contract has no exact specialist pool.",
      "Pin at least one reviewed specialist and model configuration in a new contract.",
      "dependency_missing",
    );
  }
  return {
    allowedActionClasses: allowedRaw as ActionClassId[],
    prohibitedActionClasses: prohibited,
    destructivePolicy: destructivePolicy as CanonicalActionPolicy["destructivePolicy"],
    boundedDestructiveTargets: policyStringArray(
      policy.boundedDestructiveTargets,
      "bounded destructive targets",
    ),
    specialistAgentIds: specialists,
  };
}

function liveProviderMatches(
  projection: RuntimeProjectionInput,
  binding: LocalAutonomousActionBinding,
  nowMs: number,
): boolean {
  return projection.readiness.providers.some((provider) => {
    const attestedAt = Date.parse(provider.attestedAt ?? "");
    const expiresAt = Date.parse(provider.expiresAt ?? "");
    return provider.id === binding.providerId
      && provider.health === "healthy"
      && provider.authenticated
      && provider.callable
      && provider.circuitState === "closed"
      && provider.enforcesAutonomousBoundary
      && provider.requestedModel === binding.modelId
      && provider.returnedModel === binding.modelId
      && provider.modelConfigurationHash === binding.modelConfigurationHash
      && typeof provider.completionProbeReceiptId === "string"
      && PUBLIC_ID.test(provider.completionProbeReceiptId)
      && Number.isFinite(attestedAt)
      && Number.isFinite(expiresAt)
      && attestedAt <= nowMs
      && expiresAt > nowMs;
  });
}

function liveBindingMatches(
  projection: RuntimeProjectionInput,
  binding: LocalAutonomousActionBinding,
  nowMs: number,
): boolean {
  const manifests = projection.capabilityManifests;
  if (!manifests || !liveProviderMatches(projection, binding, nowMs)) return false;
  let capabilities;
  try {
    capabilities = buildRuntimeCapabilityProjection(manifests, new Date(nowMs));
  } catch {
    return false;
  }
  const localProcess = isLocalProcessBinding(binding);
  const toolId = localProcess ? binding.toolId : binding.toolName;
  const mapping = capabilities.actionClasses[binding.actionClassId];
  const tool = manifests.tools.find(({ id }) => id === toolId);
  const agent = manifests.agents.find(({ id }) => id === binding.agentId);
  const provider = manifests.providers.find(({ id }) => id === binding.providerId);
  const model = provider?.models.find(({ id }) => id === binding.modelId);
  const projectedAgent = projection.agents.find(({ id }) => id === binding.agentId);
  const projectedMcp = isMcpBinding(binding)
    ? projection.mcpServers.find(({ id }) => id === binding.mcpServerId)
    : undefined;
  const projectedProvider = projection.readiness.providers.find(({ id }) =>
    id === binding.providerId);
  const heartbeat = Date.parse(projectedAgent?.lastHeartbeatAt ?? "");
  const allowedTools = Array.isArray(projectedAgent?.toolPolicy.allowedTools)
    ? projectedAgent.toolPolicy.allowedTools.filter((value): value is string => typeof value === "string")
    : [];
  const deniedTools = Array.isArray(projectedAgent?.toolPolicy.deniedTools)
    ? projectedAgent.toolPolicy.deniedTools.filter((value): value is string => typeof value === "string")
    : [];
  const approvalRequiredTools = Array.isArray(projectedAgent?.toolPolicy.approvalRequiredTools)
    ? projectedAgent.toolPolicy.approvalRequiredTools.filter((value): value is string => typeof value === "string")
    : [];
  const providerRef = `${binding.providerId}/${binding.modelId}`;
  const enforcedModelRoute = mapping.enforcedProviderModelRefs.includes(providerRef);
  const localDeterministicRoute = projectedProvider?.executionBoundary
      === "local_deterministic_policy"
    && mapping.providerModelRefs.includes(providerRef)
    && tool?.requiresModel === false
    && model?.toolCalling === false
    && model.structuredOutput === true;
  return mapping.availability === "supported"
    && mapping.enforcementReady
    && mapping.availableAgentIds.includes(binding.agentId)
    && mapping.availableToolIds.includes(toolId)
    && (localProcess || (isMcpBinding(binding)
      && mapping.mcpServerIds.includes(binding.mcpServerId)))
    && (enforcedModelRoute || localDeterministicRoute)
    && binding.capabilityIds.every((id) => agent?.capabilityIds.includes(id))
    && binding.requiredEvidenceTypeIds.every((id) => mapping.evidenceTypeIds.includes(id))
    && tool?.available === true
    && tool.locallyPolicyEnforced === true
    && (localProcess
      ? tool.mcpServerId === undefined
      : isMcpBinding(binding) && tool.mcpServerId === binding.mcpServerId)
    && tool.actionClassIds.includes(binding.actionClassId)
    && agent?.available === true
    && agent.toolIds.includes(toolId)
    && agent.modelRefs.some(({ providerId, modelId }) =>
      providerId === binding.providerId && modelId === binding.modelId)
    && model?.enforcement === "enforced_executor"
    && model.compatibleActionClassIds.includes(binding.actionClassId)
    && projectedAgent?.status === "available"
    && allowedTools.includes(toolId)
    && !deniedTools.includes(toolId)
    && !approvalRequiredTools.includes(toolId)
    && Number.isFinite(heartbeat)
    && heartbeat <= nowMs
    && heartbeat >= nowMs - 60_000
    && (localProcess || (isMcpBinding(binding) && (
      projectedMcp?.status === "healthy"
      && isSpecialistMcpExecutionPolicy(projectedMcp.policy)
      && projectedMcp.policy.assignedAgents.includes(binding.agentId)
      && projectedMcp.capabilities.includes(toolId)
    )));
}

function deterministicParameters(binding: LocalAutonomousActionBinding, target: string) {
  return Object.freeze({ ...binding.staticParameters, [binding.targetParameter]: target });
}

/**
 * Runtime bindings keep their adapter identity for live attestation and tool
 * transport checks. Signed contracts and durable assignments use the stable
 * product role that owns the action class. The internal identity remains a
 * compatibility fallback only for already-confirmed pre-roster contracts.
 */
function signedAssignmentAgentId(
  policy: CanonicalActionPolicy,
  binding: LocalAutonomousActionBinding,
): string | undefined {
  const productAgentId = productAgentIdForActionClass(binding.actionClassId);
  if (productAgentId && policy.specialistAgentIds.includes(productAgentId)) {
    return productAgentId;
  }
  return policy.specialistAgentIds.includes(binding.agentId)
    ? binding.agentId
    : undefined;
}

export interface LocalAutonomousContractPlannerOptions {
  readonly database: SqliteDatabase;
  readonly readRuntimeProjection: () => RuntimeProjectionInput;
  readonly policy: LocalAutonomousPlanningPolicy;
  /**
   * Mission-specific, read-only gate for the one reviewed exploit-validation
   * surface. A generic local-process binding is never sufficient by itself.
   */
  readonly exploitValidationPlanning?: AutonomousExploitValidationPlanningPort;
  readonly now?: () => Date;
}

/**
 * Tool-free local planner. It reads canonical policy and live manifests, then
 * emits only reviewed exact specialist bindings. It never contacts a target,
 * opens a socket, starts a process, calls a provider, or dispatches a tool.
 */
export class LocalAutonomousContractPlanner implements MissionPlannerPort {
  readonly autonomousContract = Object.freeze({
    schemaVersion: LOCAL_AUTONOMOUS_PLANNER_CONTRACT_SCHEMA_VERSION,
    plannerId: LOCAL_AUTONOMOUS_PLANNER_ID,
    planAuthority: "signed_contract_bounded_plan" as const,
    providerToolDeclarations: "none" as const,
    directToolDispatch: false as const,
  });
  readonly localPlanningBoundary: LocalAutonomousPlannerBoundary;
  readonly #policy: LocalAutonomousPlanningPolicy;
  readonly #now: () => Date;

  constructor(private readonly options: LocalAutonomousContractPlannerOptions) {
    this.#policy = validateLocalAutonomousPlanningPolicy(options.policy);
    this.#now = options.now ?? (() => new Date());
    const bindings = this.#policy.bindings.map((binding) => Object.freeze({
      bindingId: binding.bindingId,
      actionClassId: binding.actionClassId,
      agentId: binding.agentId,
      providerId: binding.providerId,
      modelId: binding.modelId,
      modelConfigurationHash: binding.modelConfigurationHash,
      ...(isLocalProcessBinding(binding)
        ? { executionBinding: "reviewed_local_process" as const, toolId: binding.toolId }
        : { mcpServerId: binding.mcpServerId, toolName: binding.toolName }),
    }));
    this.localPlanningBoundary = Object.freeze({
      schemaVersion: LOCAL_AUTONOMOUS_PLANNER_BOUNDARY_SCHEMA_VERSION,
      kind: "local_deterministic",
      providerContact: false,
      canonicalContractRequired: true,
      runtimeManifestRequired: true,
      heuristicToolArguments: false,
      policyId: this.#policy.policyId,
      policyHash: hashCanonical(this.#policy),
      bindings: Object.freeze(bindings),
    });
  }

  async plan(input: MissionPlannerInput, signal: AbortSignal): Promise<MissionPlanDraft> {
    if (signal.aborted) throw new DOMException("Autonomous local planning was cancelled", "AbortError");
    if (input.mission.journey !== "autonomous" || input.run.journey !== "autonomous") {
      throw contractError(
        "autonomous_local_planner_journey_mismatch",
        "the local Autonomous planner was invoked for a non-Autonomous run.",
        "Route Guided work to the Guided runtime; journey conversion must be explicit.",
      );
    }
    if (input.brainContext.exposureReceiptId !== undefined) {
      throw contractError(
        "autonomous_local_context_boundary_invalid",
        "the local planner received a public-provider Context Pack envelope.",
        "Use the runtime's sanitized local Context Pack boundary; do not create a provider turn.",
      );
    }
    const context = this.options.database.prepare(`
      SELECT mission_id, run_id, journey FROM memory_context_packs WHERE id = ?
    `).get(input.brainContext.contextPackId) as {
      mission_id: string | null; run_id: string | null; journey: string;
    } | undefined;
    if (
      !context || context.mission_id !== input.mission.id
      || context.run_id !== input.run.id || context.journey !== "autonomous"
    ) {
      throw contractError(
        "autonomous_local_context_pack_mismatch",
        "the planning Context Pack does not belong to this exact mission and run.",
        "Refresh the scoped planning Context Pack before retrying in a new run.",
        "scope_conflict",
      );
    }
    const canonicalContextItems = this.options.database.prepare(`
      SELECT mci.node_id, mn.node_type
      FROM memory_context_items mci
      JOIN memory_nodes mn ON mn.id = mci.node_id
      WHERE mci.context_pack_id = ?
    `).all(input.brainContext.contextPackId) as Array<{
      node_id: string;
      node_type: string;
    }>;
    const canonicalContextTypes = new Map(
      canonicalContextItems.map((item) => [item.node_id, item.node_type]),
    );
    const envelopeNodeIds = input.brainContext.items.map((item) => item.nodeId);
    if (
      new Set(envelopeNodeIds).size !== envelopeNodeIds.length
      || input.brainContext.items.some((item) =>
        canonicalContextTypes.get(item.nodeId) !== item.nodeType)
    ) {
      throw contractError(
        "autonomous_local_context_items_mismatch",
        "the local Context Pack envelope does not match its canonical persisted items.",
        "Refresh the signed, scope-safe Context Pack before planning a new run.",
        "scope_conflict",
      );
    }
    const memoryInfluence = planningMemoryInfluence(input.brainContext);
    const contract = this.options.database.prepare(`
      SELECT r.mission_id, r.journey, r.contract_id, r.contract_version_bound,
        r.contract_hash_bound, mc.version, mc.state, mc.contract_hash,
        mc.action_policy_json, mc.budgets_json
      FROM runs r
      JOIN mission_contracts mc ON mc.id = r.contract_id AND mc.mission_id = r.mission_id
      WHERE r.id = ? AND r.mission_id = ?
    `).get(input.run.id, input.mission.id) as CanonicalContractRow | undefined;
    if (
      !contract || contract.journey !== "autonomous" || contract.state !== "confirmed"
      || !contract.contract_id
      || contract.contract_version_bound !== contract.version
      || contract.contract_hash_bound !== contract.contract_hash
    ) {
      throw contractError(
        "autonomous_local_contract_binding_invalid",
        "the run is not bound to one unchanged confirmed Autonomous contract.",
        "Create a new run from the reviewed contract; never redefine a live run's authority.",
      );
    }
    if (input.mission.authorizationStatus !== "verified") {
      throw contractError(
        "autonomous_local_authorization_invalid",
        "mission authorization is not currently verified.",
        "Restore explicit authorization before starting a new run.",
        "scope_conflict",
      );
    }
    if (input.mission.allowedTargets.length === 0) {
      throw contractError(
        "autonomous_local_scope_empty",
        "the mission has no exact allowed target.",
        "Add at least one authorized target and launch a new contract.",
        "scope_conflict",
      );
    }
    const allowedTargets = [...new Set(input.mission.allowedTargets.map((target) => target.trim()))];
    const prohibitedTargets = new Set(input.mission.prohibitedTargets.map((target) => target.trim()));
    if (allowedTargets.some((target) => !target || prohibitedTargets.has(target))) {
      throw contractError(
        "autonomous_local_scope_ambiguous",
        "allowed and prohibited target scope overlaps or contains an empty value.",
        "Resolve the normalized target scope in a versioned contract.",
        "scope_conflict",
      );
    }
    if (input.mission.successCriteria.length === 0) {
      throw contractError(
        "autonomous_local_success_criteria_missing",
        "the mission has no measurable success criteria.",
        "Accept recommended criteria or define explicit evidence-backed completion criteria.",
        "invalid_input",
      );
    }
    const policy = canonicalPolicy(contract);
    const exactIpReconPairMounted = AUTONOMOUS_IP_RECON_EXACT_PROCESS_BINDINGS.every(
      (expected) => this.#policy.bindings.some((binding) =>
        isLocalProcessBinding(binding)
        && binding.actionClassId === expected.actionClassId
        && binding.toolId === expected.toolId),
    );
    const ipReconClassCount = AUTONOMOUS_IP_RECON_ACTION_CLASSES.filter((actionClassId) =>
      policy.allowedActionClasses.includes(actionClassId)).length;
    if (exactIpReconPairMounted
      && ipReconClassCount !== 0
      && ipReconClassCount !== AUTONOMOUS_IP_RECON_ACTION_CLASSES.length) {
      throw contractError(
        "autonomous_ip_recon_contract_incomplete",
        "the bounded IP reconnaissance route requires both host discovery and port/service enumeration in the signed contract.",
        "Use the complete Safe IP Recon action-class pair or remove both classes from this run.",
        "policy_denied",
      );
    }
    if (exactIpReconPairMounted && ipReconClassCount > 0 && (
      allowedTargets.length !== 1
      || !exactAutonomousIpReconTarget(allowedTargets[0]!)
    )) {
      throw contractError(
        "autonomous_ip_recon_scope_not_single_host",
        "the bounded IP reconnaissance route requires exactly one normalized IP address or hostname.",
        "Create a separate run for each exact host; CIDRs, URLs, environment labels, and target batches are not accepted by this route.",
        "scope_conflict",
      );
    }
    const exactWebSurfacePairMounted = AUTONOMOUS_WEB_SURFACE_EXACT_PROCESS_BINDINGS.every(
      (expected) => this.#policy.bindings.some((binding) =>
        isLocalProcessBinding(binding)
        && binding.actionClassId === expected.actionClassId
        && binding.toolId === expected.toolId),
    );
    const webSurfaceClassCount = AUTONOMOUS_WEB_SURFACE_ACTION_CLASSES.filter((actionClassId) =>
      policy.allowedActionClasses.includes(actionClassId)).length;
    const endpointDiscoveryMounted = this.#policy.bindings.some((binding) =>
      isLocalProcessBinding(binding)
      && binding.actionClassId === AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS
      && binding.toolId === AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE);
    const endpointDiscoveryAllowed = policy.allowedActionClasses.includes(
      AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
    );
    if (exactWebSurfacePairMounted
      && webSurfaceClassCount !== 0
      && webSurfaceClassCount !== AUTONOMOUS_WEB_SURFACE_ACTION_CLASSES.length) {
      throw contractError(
        "autonomous_web_surface_contract_incomplete",
        "the verified web continuation requires both HTTP metadata and technology fingerprinting in the signed contract.",
        "Authorize the complete read-only web pair or remove both classes from this run; the runtime will not bypass its evidence dependency.",
        "policy_denied",
      );
    }
    if (endpointDiscoveryAllowed && (
      !endpointDiscoveryMounted
      || !exactWebSurfacePairMounted
      || webSurfaceClassCount !== AUTONOMOUS_WEB_SURFACE_ACTION_CLASSES.length
    )) {
      throw contractError(
        "autonomous_endpoint_discovery_contract_incomplete",
        "bounded endpoint discovery requires the reviewed HTTP metadata and technology-fingerprint phases in the same signed contract.",
        "Authorize the complete evidence-derived web sequence or remove endpoint discovery from this run.",
        "policy_denied",
      );
    }
    const exactFullTcpMounted = this.#policy.bindings.some((binding) =>
      isLocalProcessBinding(binding)
      && binding.actionClassId === "port_service_enumeration"
      && binding.toolId === AUTONOMOUS_FULL_TCP_COMPOSITE_TOOL_ID);
    const cveApplicabilityMounted = this.#policy.bindings.some((binding) =>
      isLocalProcessBinding(binding)
      && binding.actionClassId === AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS
      && binding.toolId === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE);
    const cveApplicabilityAllowed = policy.allowedActionClasses.includes(
      AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
    );
    const vulnerabilityAssessmentMounted = this.#policy.bindings.some((binding) =>
      isLocalProcessBinding(binding)
      && binding.actionClassId === AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS
      && binding.toolId === AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE);
    const vulnerabilityAssessmentAllowed = policy.allowedActionClasses.includes(
      AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
    );
    const exploitValidationMounted = this.#policy.bindings.some((binding) =>
      isLocalProcessBinding(binding)
      && binding.actionClassId === AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS
      && binding.toolId === AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE
      && binding.idempotent === false
      && binding.destructive === false);
    const exploitValidationAllowed = policy.allowedActionClasses.includes(
      AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
    );
    const postExploitClassCount =
      AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES.filter((actionClassId) =>
        policy.allowedActionClasses.includes(actionClassId)).length;
    const exactPostExploitRouteMounted =
      AUTONOMOUS_LINUX_POST_EXPLOIT_EXACT_PROCESS_BINDINGS.every(
        (expected) => this.#policy.bindings.some((binding) =>
          isLocalProcessBinding(binding)
          && binding.actionClassId === expected.actionClassId
          && binding.toolId === expected.toolId
          && binding.idempotent === (
            expected.toolId === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
            || expected.toolId === AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE
          )
          && binding.destructive === false),
      );
    if (
      postExploitClassCount !== 0
      && postExploitClassCount !==
        AUTONOMOUS_LINUX_POST_EXPLOIT_ACTION_CLASSES.length
    ) {
      throw contractError(
        "autonomous_linux_post_exploit_contract_incomplete",
        "the candidate-bound Linux route requires session identity, hash-only user proof, privilege escalation, hash-only root proof, and verified cleanup in one signed contract.",
        "Authorize the complete reviewed post-exploit action-class set or remove all four classes from this run.",
        "policy_denied",
      );
    }
    if (postExploitClassCount > 0 && (
      !exactPostExploitRouteMounted
      || !exploitValidationAllowed
      || !exploitValidationMounted
    )) {
      throw contractError(
        "autonomous_linux_post_exploit_route_unavailable",
        "the full candidate-bound Linux route has no complete live five-operation transport and exploit-validation dependency.",
        "Restore the hash-pinned typed transport and exact exploit route before launching this contract.",
        "dependency_missing",
      );
    }
    if (
      postExploitClassCount > 0
      && (allowedTargets.length !== 1 || isIP(allowedTargets[0]!) === 0)
    ) {
      throw contractError(
        "autonomous_linux_post_exploit_scope_not_single_ip",
        "the candidate-bound Linux route accepts exactly one canonical IP target.",
        "Create one disposable-lab run for the exact IP; labels, URLs, CIDRs, and target batches are not accepted.",
        "scope_conflict",
      );
    }
    if ((exactWebSurfacePairMounted && webSurfaceClassCount > 0 || endpointDiscoveryAllowed)
      && (!exactFullTcpMounted
        || !policy.allowedActionClasses.includes("port_service_enumeration"))) {
      throw contractError(
        "autonomous_web_surface_full_tcp_required",
        "the verified web continuation requires the reviewed Full-TCP baseline in the same signed contract.",
        "Authorize port and service enumeration through the exact Full-TCP composite, or remove both web classes from this run.",
        "policy_denied",
      );
    }
    if ((exactWebSurfacePairMounted && webSurfaceClassCount > 0 || endpointDiscoveryAllowed) && (
      allowedTargets.length !== 1 || isIP(allowedTargets[0]!) === 0
    )) {
      throw contractError(
        "autonomous_web_surface_scope_not_single_ip",
        "the derived-origin web continuation requires exactly one canonical IP mission target.",
        "Create a separate exact-IP run; the web phase derives origins only from that run's verified Full-TCP evidence.",
        "scope_conflict",
      );
    }
    if (cveApplicabilityAllowed && (
      !cveApplicabilityMounted
      || !exactFullTcpMounted
      || !policy.allowedActionClasses.includes("port_service_enumeration")
    )) {
      throw contractError(
        "autonomous_cve_applicability_full_tcp_required",
        "CVE applicability requires the reviewed Full-TCP service/version evidence phase in the same signed contract.",
        "Authorize the exact Full-TCP baseline or remove CVE applicability from this run; the runtime will not infer versions from raw output.",
        "policy_denied",
      );
    }
    if (cveApplicabilityAllowed && (allowedTargets.length !== 1 || isIP(allowedTargets[0]!) === 0)) {
      throw contractError(
        "autonomous_cve_applicability_scope_not_single_ip",
        "CVE applicability requires exactly one canonical IP mission target with verified service/version evidence.",
        "Create a separate exact-IP run; candidate matching never expands scope or accepts an unverified target label.",
        "scope_conflict",
      );
    }
    if (vulnerabilityAssessmentAllowed && (
      !vulnerabilityAssessmentMounted
      || !exactFullTcpMounted
      || !exactWebSurfacePairMounted
      || webSurfaceClassCount !== AUTONOMOUS_WEB_SURFACE_ACTION_CLASSES.length
      || !policy.allowedActionClasses.includes("port_service_enumeration")
    )) {
      throw contractError(
        "autonomous_vulnerability_assessment_dependencies_incomplete",
        "the bounded vulnerability assessment requires the reviewed Full-TCP, HTTP metadata, and technology-fingerprint phases in the same signed contract.",
        "Authorize the complete evidence-derived web sequence or remove vulnerability and configuration assessment from this run.",
        "policy_denied",
      );
    }
    if (vulnerabilityAssessmentAllowed
      && (allowedTargets.length !== 1 || isIP(allowedTargets[0]!) === 0)) {
      throw contractError(
        "autonomous_vulnerability_assessment_scope_not_single_ip",
        "the bounded vulnerability assessment requires exactly one canonical IP mission target.",
        "Create a separate exact-IP run; assessment origins are derived only from that run's verified HTTP evidence.",
        "scope_conflict",
      );
    }
    if (exploitValidationAllowed && (
      !exploitValidationMounted
      || !cveApplicabilityMounted
      || !cveApplicabilityAllowed
      || !exactFullTcpMounted
      || !policy.allowedActionClasses.includes("port_service_enumeration")
    )) {
      throw contractError(
        "autonomous_exploit_validation_dependencies_incomplete",
        "exploit validation requires the exact reviewed sandbox binding plus current-run Full-TCP and CVE-applicability evidence phases in the same signed contract.",
        "Authorize the complete evidence-derived route and mount the exact sandbox binding, or keep exploit validation Guided only for this run.",
        "policy_denied",
      );
    }
    if (exploitValidationAllowed
      && (allowedTargets.length !== 1 || isIP(allowedTargets[0]!) === 0)) {
      throw contractError(
        "autonomous_exploit_validation_scope_not_single_ip",
        "the reviewed exploit-validation route accepts exactly one canonical IP target.",
        "Create a separate exact-IP disposable-lab run; this route never expands a label, CIDR, URL, or target batch.",
        "scope_conflict",
      );
    }
    let exploitPlanningReadiness:
      AutonomousExploitValidationPlanningReadiness | undefined;
    if (exploitValidationAllowed) {
      exploitPlanningReadiness = this.options.exploitValidationPlanning?.inspect({
        missionId: input.mission.id,
        runId: input.run.id,
        contractId: contract.contract_id,
        exactTarget: allowedTargets[0]!,
        contextPackId: input.brainContext.contextPackId,
        contextNodeIds: input.brainContext.items.map(({ nodeId }) => nodeId),
      }) ?? {
        schemaVersion:
          "ti-scale.autonomous-exploit-validation-planning-readiness.v1",
        ready: false,
        code: "active_vault_procedure_missing",
        explanation:
          "Exploit validation is deferred because no canonical mission-specific ScriptArtifact/Vault planning gate is mounted.",
        remediation:
          "Mount the read-only canonical exploit planning gate and replan after the exact procedure is synchronized.",
      };
    }
    const projection = this.options.readRuntimeProjection();
    const now = this.#now();
    const nowMs = now.getTime();
    if (!Number.isFinite(nowMs)) throw new RangeError("Local planner time is invalid");

    const unorderedLiveBindings = policy.allowedActionClasses.flatMap((actionClassId) =>
      this.#policy.bindings.filter((binding) =>
        binding.actionClassId === actionClassId
        && !policy.prohibitedActionClasses.includes(binding.actionClassId)
        && signedAssignmentAgentId(policy, binding) !== undefined
        && liveBindingMatches(projection, binding, nowMs)));
    const orderedLiveBindings = (exactWebSurfacePairMounted && webSurfaceClassCount > 0)
        || endpointDiscoveryAllowed || cveApplicabilityAllowed
        || vulnerabilityAssessmentAllowed || exploitValidationAllowed
      ? orderLocalAutonomousBindingsForDependencies(unorderedLiveBindings)
      : unorderedLiveBindings;
    const unavailableClasses = policy.allowedActionClasses.filter((actionClassId) =>
      !orderedLiveBindings.some((binding) => binding.actionClassId === actionClassId));
    if (unavailableClasses.length > 0) {
      throw contractError(
        "autonomous_local_action_binding_unavailable",
        `no exact live reviewed binding exists for: ${unavailableClasses.join(", ")}.`,
        "Restore the pinned specialist/model/execution route or amend the contract to a supported action set.",
        "dependency_missing",
      );
    }
    const liveBindings = orderedLiveBindings.filter((binding) =>
      (
        binding.actionClassId !== AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS
        || exploitPlanningReadiness?.ready === true
      )
      && !(
        isLocalProcessBinding(binding)
        && AUTONOMOUS_LINUX_POST_EXPLOIT_TOOL_IDS.has(binding.toolId)
      ));

    const steps: MissionPlanDraft["steps"][number][] = [];
    for (const binding of liveBindings) {
      for (const target of allowedTargets) {
        const assignedAgentId = signedAssignmentAgentId(policy, binding);
        if (!assignedAgentId) continue;
        const targetKind = classifyTarget(target);
        if (!binding.targetKinds.includes(targetKind)) continue;
        if (binding.destructive) {
          const bounded = policy.boundedDestructiveTargets.includes(target);
          if (policy.destructivePolicy !== "bounded_lab_only" || !bounded) {
            throw contractError(
              "autonomous_local_destructive_action_outside_bound",
              `${binding.title} is destructive but ${target} is not an exact bounded disposable-lab target.`,
              "Prohibit the class or create a separately bounded lab-only contract for the exact target.",
              "scope_conflict",
            );
          }
        }
        const ordinal = steps.length;
        steps.push({
          phase: binding.phase,
          title: `${binding.title} — ${target}`,
          objective: `${binding.objective} Exact target: ${target}.`,
          explanation: binding.explanation,
          rationale: `${binding.rationale} This route was selected from reviewed policy ${this.#policy.policyId}; ${memoryInfluence.rationale}. No provider or tool was contacted while planning.`,
          successCriteria: [...binding.successCriteria, ...memoryInfluence.successCriteria],
          dependencyOrdinals: ordinal === 0 ? [] : [ordinal - 1],
          assignedAgentId,
          riskClass: binding.riskClass,
          reversibility: binding.reversibility,
          action: {
            actionType: isLocalProcessBinding(binding)
              ? binding.toolId
              : binding.actionClassId,
            actionClass: binding.actionClassId,
            target,
            arguments: binding.actionClassId === AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS
              && exploitPlanningReadiness?.ready === true
              ? Object.freeze({ ...exploitPlanningReadiness.arguments })
              : isLocalProcessBinding(binding)
              ? {
                  schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
                  executionBinding: "reviewed_local_process" as const,
                  toolId: binding.toolId,
                  parameters: deterministicParameters(binding, target),
                }
              : {
                  mcpServer: binding.mcpServerId,
                  toolName: binding.toolName,
                  parameters: deterministicParameters(binding, target),
                },
            intentSummary: `${binding.title} for exact authorized target ${target}`,
            kind: "tool",
            idempotent: binding.idempotent,
            destructive: binding.destructive,
          },
        });
      }
    }
    if (steps.length === 0) {
      if (exploitValidationAllowed && exploitPlanningReadiness?.ready === false) {
        throw contractError(
          `autonomous_exploit_validation_${exploitPlanningReadiness.code}`,
          exploitPlanningReadiness.explanation,
          exploitPlanningReadiness.remediation,
          exploitPlanningReadiness.code === "disposable_target_required"
            ? "scope_conflict"
            : "dependency_missing",
        );
      }
      throw contractError(
        "autonomous_local_target_binding_ambiguous",
        "none of the reviewed action bindings applies to the supplied target types.",
        "Use a supported exact target type or add and attest a reviewed declarative binding.",
        "dependency_missing",
      );
    }
    if (steps.length > this.#policy.maximumSteps) {
      throw contractError(
        "autonomous_local_plan_exceeds_bound",
        `the deterministic plan requires ${steps.length} steps, above the reviewed limit of ${this.#policy.maximumSteps}.`,
        "Narrow the targets or action classes in a versioned contract; the planner will not silently truncate work.",
        "invalid_input",
      );
    }
    const receipt = createHash("sha256").update([
      contract.contract_hash,
      this.localPlanningBoundary.policyHash,
      input.brainContext.contextPackId,
      ...steps.map((step) => hashCanonical(step)),
    ].join("\u0000"), "utf8").digest("hex");
    return {
      strategySummary: `Execute ${steps.length} deterministic reviewed specialist ${steps.length === 1 ? "step" : "steps"} under contract v${contract.version} (${contract.contract_hash.slice(0, 12)}…) and planning receipt ${receipt.slice(0, 12)}….${exploitPlanningReadiness?.ready === false ? " Exploit validation remains deferred until its exact candidate gate is ready." : ""}`,
      rationaleSummary: `The local planner used the reviewed dependency order, exact target scope, signed action classes, reviewed policy ${this.#policy.policyId}, live specialist/model/execution mappings, and Context Pack ${input.brainContext.contextPackId}; ${memoryInfluence.rationale}. It made no provider call and dispatched no work.${exploitPlanningReadiness?.ready === false ? ` ${exploitPlanningReadiness.explanation}` : ""}`,
      steps,
      // A finite contract budget still needs an exact accounting record. This
      // planner makes no provider call, so zero is authoritative rather than
      // missing telemetry (which the runtime correctly treats as unsafe).
      providerUsage: {
        providerTurns: 0,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        billedCostUsd: 0,
        exactTokenUsage: true,
        exactCostUsage: true,
      },
      planningAttribution: {
        contextPackIds: [input.brainContext.contextPackId],
        citations: memoryInfluence.citations,
      },
    };
  }
}

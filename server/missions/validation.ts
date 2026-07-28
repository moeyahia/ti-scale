import { isIP } from "node:net";
import { MissionValidationError } from "./errors";
import { parseGuidedReconnaissanceSelection } from "./GuidedReconnaissance";
import type {
  AutonomousMissionRequest,
  GuidedMissionRequest,
  MissionCreateRequest,
} from "./types";
import {
  AUTONOMOUS_LOCAL_PLANNING_SELECTION,
  type AgentModelAssignmentSelection,
  type AutonomousPlanningSelection,
} from "../model-config";

type UnknownRecord = Record<string, unknown>;

const MAX_TITLE_LENGTH = 240;
const MAX_OBJECTIVE_LENGTH = 20_000;
const MAX_ITEM_LENGTH = 4_000;
const MAX_LIST_ITEMS = 250;
const ENVIRONMENT_CLASSIFICATIONS = [
  "client_or_public",
  "internal",
  "htb",
  "ctf",
  "local_disposable_lab",
] as const;
const DISPOSABLE_ENVIRONMENT_CLASSIFICATIONS = new Set([
  "htb",
  "ctf",
  "local_disposable_lab",
]);

function isRecord(value: unknown): value is UnknownRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requiredText(
  value: unknown,
  path: string,
  issues: string[],
  maximum = MAX_ITEM_LENGTH,
): string {
  if (typeof value !== "string" || !value.trim()) {
    issues.push(`${path} must be a non-empty string`);
    return "";
  }
  const result = value.trim();
  if (result.length > maximum) issues.push(`${path} exceeds ${maximum} characters`);
  return result;
}

function optionalText(
  value: unknown,
  path: string,
  issues: string[],
  maximum = MAX_ITEM_LENGTH,
): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return requiredText(value, path, issues, maximum) || undefined;
}

function requiredLiteral<const T extends string>(
  value: unknown,
  expected: T,
  path: string,
  issues: string[],
): T {
  if (value !== expected) issues.push(`${path} must be ${expected}`);
  return expected;
}

function requiredChoice<const T extends string>(
  value: unknown,
  allowed: readonly T[],
  path: string,
  issues: string[],
): T {
  if (typeof value === "string" && allowed.includes(value as T)) return value as T;
  issues.push(`${path} must be one of: ${allowed.join(", ")}`);
  return allowed[0]!;
}

function stringList(
  value: unknown,
  path: string,
  issues: string[],
  options: { readonly required?: boolean } = {},
): string[] {
  if (!Array.isArray(value)) {
    issues.push(`${path} must be an array of strings`);
    return [];
  }
  if (value.length > MAX_LIST_ITEMS) {
    issues.push(`${path} cannot contain more than ${MAX_LIST_ITEMS} items`);
  }
  const result: string[] = [];
  const seen = new Set<string>();
  for (const [index, item] of value.slice(0, MAX_LIST_ITEMS).entries()) {
    const parsed = requiredText(item, `${path}[${index}]`, issues);
    if (!parsed) continue;
    const key = parsed.toLocaleLowerCase("en-US");
    if (!seen.has(key)) {
      seen.add(key);
      result.push(parsed);
    }
  }
  if (options.required && result.length === 0) {
    issues.push(`${path} must contain at least one value`);
  }
  return result;
}

function finiteNumber(
  value: unknown,
  path: string,
  issues: string[],
  options: {
    readonly integer?: boolean;
    readonly minimum: number;
    readonly maximum: number;
    readonly optional?: boolean;
  },
): number | undefined {
  if (options.optional && (value === undefined || value === null || value === "")) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    issues.push(`${path} must be a finite number`);
    return undefined;
  }
  if (options.integer && !Number.isSafeInteger(value)) {
    issues.push(`${path} must be an integer`);
  }
  if (value < options.minimum || value > options.maximum) {
    issues.push(`${path} must be between ${options.minimum} and ${options.maximum}`);
  }
  return value;
}

function overlap(left: readonly string[], right: readonly string[]): string[] {
  const rightSet = new Set(right.map((value) => value.toLocaleLowerCase("en-US")));
  return left.filter((value) => rightSet.has(value.toLocaleLowerCase("en-US")));
}

function targetKey(value: string): string {
  const trimmed = value.trim().normalize("NFKC");
  try {
    const url = new URL(trimmed);
    url.hostname = url.hostname.toLocaleLowerCase("en-US");
    return url.toString();
  } catch {
    return trimmed.toLocaleLowerCase("en-US");
  }
}

function uniqueTargets(values: readonly string[]): string[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    const key = targetKey(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function targetOverlap(left: readonly string[], right: readonly string[]): string[] {
  const rightSet = new Set(right.map(targetKey));
  return left.filter((value) => rightSet.has(targetKey(value)));
}

function parseAgentModelAssignments(
  value: unknown,
  issues: string[],
  options: { readonly allowMissing: boolean },
): AgentModelAssignmentSelection[] {
  if (value === undefined && options.allowMissing) return [];
  if (!Array.isArray(value)) {
    issues.push("contract.agentModelAssignments must be an array");
    return [];
  }
  if (value.length > MAX_LIST_ITEMS) {
    issues.push(`contract.agentModelAssignments cannot contain more than ${MAX_LIST_ITEMS} items`);
  }
  const assignments: AgentModelAssignmentSelection[] = [];
  const seen = new Set<string>();
  for (const [index, candidate] of value.slice(0, MAX_LIST_ITEMS).entries()) {
    const path = `contract.agentModelAssignments[${index}]`;
    if (!isRecord(candidate)) {
      issues.push(`${path} must be an object`);
      continue;
    }
    const unexpected = Object.keys(candidate).filter((key) =>
      !["agentId", "primaryConfigurationId", "fallbackConfigurationId", "source"].includes(key));
    if (unexpected.length > 0) {
      issues.push(`${path} contains unsupported fields: ${unexpected.sort().join(", ")}`);
    }
    const agentId = requiredText(candidate.agentId, `${path}.agentId`, issues, 200);
    const primaryConfigurationId = requiredText(
      candidate.primaryConfigurationId,
      `${path}.primaryConfigurationId`,
      issues,
      240,
    );
    let fallbackConfigurationId: string | null = null;
    if (candidate.fallbackConfigurationId !== null) {
      if (candidate.fallbackConfigurationId === undefined) {
        issues.push(`${path}.fallbackConfigurationId must be a string or null`);
      } else {
        fallbackConfigurationId = requiredText(
          candidate.fallbackConfigurationId,
          `${path}.fallbackConfigurationId`,
          issues,
          240,
        ) || null;
      }
    }
    if (
      agentId
      && !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u.test(agentId)
    ) {
      issues.push(`${path}.agentId is not a valid stable specialist ID`);
    }
    for (const [label, identifier] of [
      ["primaryConfigurationId", primaryConfigurationId],
      ["fallbackConfigurationId", fallbackConfigurationId],
    ] as const) {
      if (
        identifier
        && !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,239}$/u.test(identifier)
      ) {
        issues.push(`${path}.${label} is not a valid stable configuration ID`);
      }
    }
    if (fallbackConfigurationId === primaryConfigurationId) {
      issues.push(`${path}.fallbackConfigurationId must differ from the primary configuration`);
    }
    const source = candidate.source;
    if (
      source !== undefined
      && source !== "recommended"
      && source !== "inherited"
      && source !== "operator_override"
    ) {
      issues.push(`${path}.source must be recommended, inherited, or operator_override`);
    }
    if (seen.has(agentId)) {
      issues.push(`contract.agentModelAssignments contains duplicate agent ${agentId}`);
      continue;
    }
    seen.add(agentId);
    assignments.push({
      agentId,
      primaryConfigurationId,
      fallbackConfigurationId,
      ...(source === "recommended"
        || source === "inherited"
        || source === "operator_override"
        ? { source }
        : {}),
    });
  }
  return assignments.sort((left, right) =>
    left.agentId.localeCompare(right.agentId));
}

function parseAutonomousPlanningSelection(
  value: unknown,
  issues: string[],
): AutonomousPlanningSelection {
  if (value === undefined) return AUTONOMOUS_LOCAL_PLANNING_SELECTION;
  const path = "contract.planningSelection";
  if (!isRecord(value)) {
    issues.push(`${path} must be an object`);
    return AUTONOMOUS_LOCAL_PLANNING_SELECTION;
  }
  if (value.route === "local_deterministic") {
    const expected = new Set([
      "route",
      "plannerId",
      "enforcementMode",
      "disclosureClass",
      "executionAuthority",
    ]);
    const unexpected = Object.keys(value).filter((key) => !expected.has(key));
    if (unexpected.length > 0) {
      issues.push(`${path} contains unsupported fields for local_deterministic: ${unexpected.sort().join(", ")}`);
    }
    return {
      route: "local_deterministic",
      plannerId: requiredLiteral(
        value.plannerId,
        "ti-scale.local-autonomous-contract-planner.v1",
        `${path}.plannerId`,
        issues,
      ),
      enforcementMode: requiredLiteral(
        value.enforcementMode,
        "local_policy",
        `${path}.enforcementMode`,
        issues,
      ),
      disclosureClass: requiredLiteral(
        value.disclosureClass,
        "local_only",
        `${path}.disclosureClass`,
        issues,
      ),
      executionAuthority: requiredLiteral(
        value.executionAuthority,
        "none",
        `${path}.executionAuthority`,
        issues,
      ),
    };
  }
  if (value.route === "provider_advisory") {
    const expected = new Set([
      "route",
      "agentId",
      "primaryConfigurationId",
      "fallbackConfigurationId",
      "enforcementMode",
      "disclosureClass",
      "executionAuthority",
    ]);
    const unexpected = Object.keys(value).filter((key) => !expected.has(key));
    if (unexpected.length > 0) {
      issues.push(`${path} contains unsupported fields for provider_advisory: ${unexpected.sort().join(", ")}`);
    }
    const agentId = requiredText(value.agentId, `${path}.agentId`, issues, 200);
    const primaryConfigurationId = requiredText(
      value.primaryConfigurationId,
      `${path}.primaryConfigurationId`,
      issues,
      240,
    );
    let fallbackConfigurationId: string | null = null;
    if (value.fallbackConfigurationId !== null) {
      if (value.fallbackConfigurationId === undefined) {
        issues.push(`${path}.fallbackConfigurationId must be a string or null`);
      } else {
        fallbackConfigurationId = requiredText(
          value.fallbackConfigurationId,
          `${path}.fallbackConfigurationId`,
          issues,
          240,
        ) || null;
      }
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u.test(agentId)) {
      issues.push(`${path}.agentId is not a valid stable agent ID`);
    }
    for (const [label, identifier] of [
      ["primaryConfigurationId", primaryConfigurationId],
      ["fallbackConfigurationId", fallbackConfigurationId],
    ] as const) {
      if (
        identifier
        && !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,239}$/u.test(identifier)
      ) {
        issues.push(`${path}.${label} is not a valid stable configuration ID`);
      }
    }
    if (fallbackConfigurationId === primaryConfigurationId) {
      issues.push(`${path}.fallbackConfigurationId must differ from the primary configuration`);
    }
    return {
      route: "provider_advisory",
      agentId,
      primaryConfigurationId,
      fallbackConfigurationId,
      enforcementMode: requiredLiteral(
        value.enforcementMode,
        "advisor_only",
        `${path}.enforcementMode`,
        issues,
      ),
      disclosureClass: requiredChoice(
        value.disclosureClass,
        ["public_only", "sanitized_internal"] as const,
        `${path}.disclosureClass`,
        issues,
      ),
      executionAuthority: requiredLiteral(
        value.executionAuthority,
        "none",
        `${path}.executionAuthority`,
        issues,
      ),
    };
  }
  issues.push(`${path}.route must be local_deterministic or provider_advisory`);
  return AUTONOMOUS_LOCAL_PLANNING_SELECTION;
}

function isLegacyDisposableLabReference(value: string): boolean {
  return /^(?:lab|htb|thm|ctf):\S+$/iu.test(value.trim());
}

function isExactHostTarget(value: string): boolean {
  const target = value.trim();
  if (isIP(target) > 0) return true;
  if (isLegacyDisposableLabReference(target)) return true;
  if (
    !target
    || target.includes("/")
    || target.includes("://")
    || target.includes(":")
    || target.length > 253
  ) return false;
  return target.split(".").every((part) =>
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(part));
}

function parseAutonomous(
  root: UnknownRecord,
  issues: string[],
  options: {
    readonly allowEmptyActionClasses: boolean;
    readonly allowLegacyUnsignedAgentModels: boolean;
  },
): AutonomousMissionRequest {
  const authorization = isRecord(root.authorization) ? root.authorization : {};
  if (!isRecord(root.authorization)) issues.push("authorization must be an object");
  const contract = isRecord(root.contract) ? root.contract : {};
  if (!isRecord(root.contract)) issues.push("contract must be an object");
  const outcomeProfile = contract.outcomeProfile === undefined
    ? undefined
    : requiredChoice(
        contract.outcomeProfile,
        ["assessment", "complete_engagement"] as const,
        "contract.outcomeProfile",
        issues,
      );

  const allowedTargets = uniqueTargets(stringList(
    authorization.allowedTargets,
    "authorization.allowedTargets",
    issues,
    { required: true },
  ));
  const prohibitedTargets = uniqueTargets(stringList(
    authorization.prohibitedTargets,
    "authorization.prohibitedTargets",
    issues,
  ));
  if (targetOverlap(allowedTargets, prohibitedTargets).length > 0) {
    issues.push("allowed and prohibited targets must not overlap");
  }
  const environmentClassification = authorization.environmentClassification === undefined
    ? undefined
    : requiredChoice(
        authorization.environmentClassification,
        ENVIRONMENT_CLASSIFICATIONS,
        "authorization.environmentClassification",
        issues,
      );

  const allowedActionClasses = stringList(
    contract.allowedActionClasses,
    "contract.allowedActionClasses",
    issues,
    { required: !options.allowEmptyActionClasses },
  );
  const prohibitedActionClasses = stringList(
    contract.prohibitedActionClasses,
    "contract.prohibitedActionClasses",
    issues,
  );
  if (overlap(allowedActionClasses, prohibitedActionClasses).length > 0) {
    issues.push("allowed and prohibited action classes must not overlap");
  }
  const destructivePolicy = requiredChoice(
    contract.destructivePolicy,
    ["prohibited", "validate_without_executing", "bounded_lab_only"] as const,
    "contract.destructivePolicy",
    issues,
  );
  const boundedDestructiveTargets = uniqueTargets(stringList(
    contract.boundedDestructiveTargets ?? [],
    "contract.boundedDestructiveTargets",
    issues,
  ));
  const outsideBoundedTargets = boundedDestructiveTargets.filter((target) =>
    !allowedTargets.some((allowed) => targetKey(allowed) === targetKey(target)));
  if (outsideBoundedTargets.length > 0) {
    issues.push("contract.boundedDestructiveTargets must be inside the allowed target scope");
  }
  if (destructivePolicy === "bounded_lab_only" && boundedDestructiveTargets.length === 0) {
    issues.push("bounded_lab_only requires at least one exact bounded destructive target");
  }
  if (destructivePolicy !== "bounded_lab_only" && boundedDestructiveTargets.length > 0) {
    issues.push("bounded destructive targets are valid only with bounded_lab_only policy");
  }
  if (destructivePolicy === "bounded_lab_only") {
    const explicitlyDisposable = environmentClassification !== undefined
      && DISPOSABLE_ENVIRONMENT_CLASSIFICATIONS.has(environmentClassification);
    const legacyDisposableOnly = environmentClassification === undefined
      && boundedDestructiveTargets.every(isLegacyDisposableLabReference);
    if (!explicitlyDisposable && !legacyDisposableOnly) {
      issues.push(
        "bounded_lab_only requires authorization.environmentClassification to be htb, ctf, or local_disposable_lab; legacy lab-prefixed targets remain accepted only when no classification was supplied",
      );
    }
    if (boundedDestructiveTargets.some((target) => !isExactHostTarget(target))) {
      issues.push("contract.boundedDestructiveTargets may contain only exact host names, IP addresses, or legacy disposable-lab references");
    }
  }

  if (authorization.authorizationConfirmed !== true) {
    issues.push("authorization.authorizationConfirmed must be true");
  }
  const timeBudgetMinutes = finiteNumber(
    contract.timeBudgetMinutes,
    "contract.timeBudgetMinutes",
    issues,
    { integer: true, minimum: 1, maximum: 525_600 },
  );
  const toolCallBudget = finiteNumber(contract.toolCallBudget, "contract.toolCallBudget", issues, {
    integer: true,
    minimum: 1,
    maximum: Number.MAX_SAFE_INTEGER,
    optional: true,
  });
  const tokenBudget = finiteNumber(contract.tokenBudget, "contract.tokenBudget", issues, {
    integer: true,
    minimum: 1,
    maximum: Number.MAX_SAFE_INTEGER,
    optional: true,
  });
  const costBudget = finiteNumber(contract.costBudget, "contract.costBudget", issues, {
    minimum: 0,
    maximum: 100_000_000,
    optional: true,
  });
  const retryBudget = finiteNumber(contract.retryBudget, "contract.retryBudget", issues, {
    integer: true,
    minimum: 0,
    maximum: 100,
  });
  const replanBudget = finiteNumber(contract.replanBudget, "contract.replanBudget", issues, {
    integer: true,
    minimum: 0,
    maximum: 100,
  });
  const concurrencyLimit = finiteNumber(
    contract.concurrencyLimit,
    "contract.concurrencyLimit",
    issues,
    { integer: true, minimum: 1, maximum: 256 },
  );
  const evidenceStorageBudgetBytes = finiteNumber(
    contract.evidenceStorageBudgetBytes,
    "contract.evidenceStorageBudgetBytes",
    issues,
    { integer: true, minimum: 1_024, maximum: 10 * 1024 ** 4 },
  );
  const artifactStorageBudgetBytes = finiteNumber(
    contract.artifactStorageBudgetBytes,
    "contract.artifactStorageBudgetBytes",
    issues,
    { integer: true, minimum: 1_024, maximum: 10 * 1024 ** 4 },
  );
  const engagementId = optionalText(
    authorization.engagementId,
    "authorization.engagementId",
    issues,
    240,
  );
  const rawSpecialistAgentIds = Array.isArray(contract.specialistAgentIds)
    ? contract.specialistAgentIds
    : [];
  const specialistAgentIds = stringList(
    contract.specialistAgentIds,
    "contract.specialistAgentIds",
    issues,
  );
  if (specialistAgentIds.some((id) => !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u.test(id))) {
    issues.push("contract.specialistAgentIds contains an invalid stable specialist ID");
  }
  if (rawSpecialistAgentIds.length !== specialistAgentIds.length) {
    issues.push("contract.specialistAgentIds contains duplicate values");
  }
  specialistAgentIds.sort((left, right) => left.localeCompare(right));
  const legacyAssignmentsMissing = options.allowLegacyUnsignedAgentModels
    && (
      contract.agentModelAssignments === undefined
      || (
        Array.isArray(contract.agentModelAssignments)
        && contract.agentModelAssignments.length === 0
        && specialistAgentIds.length > 0
      )
    );
  const agentModelAssignments = parseAgentModelAssignments(
    contract.agentModelAssignments,
    issues,
    { allowMissing: options.allowLegacyUnsignedAgentModels },
  );
  if (!legacyAssignmentsMissing) {
    const assignmentAgentIds = agentModelAssignments.map(({ agentId }) => agentId);
    const missing = specialistAgentIds.filter((id) =>
      !assignmentAgentIds.includes(id));
    const extra = assignmentAgentIds.filter((id) =>
      !specialistAgentIds.includes(id));
    if (missing.length > 0) {
      issues.push(`contract.agentModelAssignments is missing selected specialists: ${missing.join(", ")}`);
    }
    if (extra.length > 0) {
      issues.push(`contract.agentModelAssignments contains unselected specialists: ${extra.join(", ")}`);
    }
  }
  const planningSelection = parseAutonomousPlanningSelection(
    contract.planningSelection,
    issues,
  );
  const memoryScopes = stringList(contract.memoryScopes, "contract.memoryScopes", issues);
  const contextNodeIds = stringList(contract.contextNodeIds, "contract.contextNodeIds", issues);
  if (contextNodeIds.some((id) => !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(id))) {
    issues.push("contract.contextNodeIds contains an invalid stable memory ID");
  }
  const allowedMemoryScopes = new Set([
    "confirmed_preferences",
    "verified_lessons",
    "confirmed_attack_knowledge",
    "verified_attack_knowledge",
    "engagement_memory",
  ]);
  if (memoryScopes.some((scope) => !allowedMemoryScopes.has(scope))) {
    issues.push("contract.memoryScopes contains an unsupported or unsafe scope");
  }
  if (memoryScopes.includes("engagement_memory") && !engagementId) {
    issues.push("engagement_memory requires authorization.engagementId");
  }
  if (contextNodeIds.length > 0 && memoryScopes.length === 0) {
    issues.push("contract.contextNodeIds requires at least one permitted memory scope");
  }

  let contractReview: AutonomousMissionRequest["contractReview"];
  if (root.contractReview !== undefined) {
    const review = isRecord(root.contractReview) ? root.contractReview : {};
    if (!isRecord(root.contractReview)) issues.push("contractReview must be an object");
    if (review.version !== 1) issues.push("contractReview.version must be 1");
    const hash = requiredText(review.hash, "contractReview.hash", issues, 64);
    if (hash && !/^[a-f0-9]{64}$/u.test(hash)) {
      issues.push("contractReview.hash must be a lowercase SHA-256 digest");
    }
    contractReview = { version: 1, hash };
  }

  return {
    journey: "autonomous",
    launch: true,
    title: requiredText(root.title, "title", issues, MAX_TITLE_LENGTH),
    objective: requiredText(root.objective, "objective", issues, MAX_OBJECTIVE_LENGTH),
    successCriteria: stringList(root.successCriteria, "successCriteria", issues, {
      required: true,
    }),
    authorization: {
      engagementId,
      ...(environmentClassification ? { environmentClassification } : {}),
      allowedTargets,
      prohibitedTargets,
      authorizationConfirmed: true,
      timeWindow: optionalText(authorization.timeWindow, "authorization.timeWindow", issues),
      dataHandling: optionalText(authorization.dataHandling, "authorization.dataHandling", issues),
    },
    contract: {
      ...(outcomeProfile ? { outcomeProfile } : {}),
      allowedActionClasses,
      prohibitedActionClasses,
      destructivePolicy,
      boundedDestructiveTargets,
      evidenceRequirements: stringList(
        contract.evidenceRequirements,
        "contract.evidenceRequirements",
        issues,
      ),
      timeBudgetMinutes: timeBudgetMinutes ?? 0,
      ...(toolCallBudget === undefined ? {} : { toolCallBudget }),
      ...(tokenBudget === undefined ? {} : { tokenBudget }),
      ...(costBudget === undefined ? {} : { costBudget }),
      retryBudget: retryBudget ?? -1,
      replanBudget: replanBudget ?? -1,
      concurrencyLimit: concurrencyLimit ?? 0,
      evidenceStorageBudgetBytes: evidenceStorageBudgetBytes ?? 0,
      artifactStorageBudgetBytes: artifactStorageBudgetBytes ?? 0,
      notificationPolicy: requiredLiteral(
        contract.notificationPolicy,
        "in_app_only",
        "contract.notificationPolicy",
        issues,
      ),
      reportingFormat: requiredLiteral(
        contract.reportingFormat,
        "ti_scale_json",
        "contract.reportingFormat",
        issues,
      ),
      dataHandlingPolicy: requiredLiteral(
        contract.dataHandlingPolicy,
        "local_private",
        "contract.dataHandlingPolicy",
        issues,
      ),
      retentionPolicy: requiredLiteral(
        contract.retentionPolicy,
        "operator_managed",
        "contract.retentionPolicy",
        issues,
      ),
      providerPolicy: requiredLiteral(
        contract.providerPolicy,
        "automatic_enforcing_only",
        "contract.providerPolicy",
        issues,
      ),
      toolPolicy: requiredLiteral(
        contract.toolPolicy,
        "contract_allowlist",
        "contract.toolPolicy",
        issues,
      ),
      specialistAgentIds,
      planningSelection,
      agentModelAssignments,
      memoryScopes,
      contextNodeIds,
      safeStopConditions: stringList(
        contract.safeStopConditions,
        "contract.safeStopConditions",
        issues,
        { required: true },
      ),
      // Deliverables are optional. A narrow executor must not invent a report
      // or artifact producer merely to satisfy a schema-level non-empty list.
      deliverables: stringList(contract.deliverables, "contract.deliverables", issues),
    },
    ...(contractReview ? { contractReview } : {}),
  };
}

function parseGuided(root: UnknownRecord, issues: string[]): GuidedMissionRequest {
  if (root.authorizationConfirmed !== true) {
    issues.push("authorizationConfirmed must be true");
  }
  const explanationDepth = root.explanationDepth;
  if (
    explanationDepth !== "concise" &&
    explanationDepth !== "balanced" &&
    explanationDepth !== "deep"
  ) {
    issues.push("explanationDepth must be concise, balanced, or deep");
  }
  const executionPreference = root.executionPreference;
  if (executionPreference !== "manual" && executionPreference !== "single_step_agent") {
    issues.push("executionPreference must be manual or single_step_agent");
  }
  const guidedReconnaissance = parseGuidedReconnaissanceSelection(root.guidedReconnaissance);
  issues.push(...guidedReconnaissance.issues);
  const target = optionalText(root.target, "target", issues);
  if (guidedReconnaissance.selection && (!target || (
    isIP(target) === 0
    && !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/u.test(target)
  ))) {
    issues.push("guidedReconnaissance requires target to be one IP address or hostname without a scheme, port, CIDR, or range");
  }
  let guidedWindowsIdentity: GuidedMissionRequest["guidedWindowsIdentity"];
  if (root.guidedWindowsIdentity !== undefined && root.guidedWindowsIdentity !== null) {
    if (!isRecord(root.guidedWindowsIdentity)) {
      issues.push("guidedWindowsIdentity must be an object");
    } else {
      const selection = root.guidedWindowsIdentity;
      const expectedKeys = new Set(["operation", "authenticationMode", "credentialReference"]);
      const unexpected = Object.keys(selection).filter((key) => !expectedKeys.has(key));
      if (unexpected.length > 0) {
        issues.push(`guidedWindowsIdentity contains unsupported fields: ${unexpected.sort().join(", ")}`);
      }
      const operations = new Set([
        "smb_share_list", "smb_identity_summary", "ldap_root_dse", "rpc_domain_info",
      ]);
      const operation = typeof selection.operation === "string" && operations.has(selection.operation)
        ? selection.operation as NonNullable<GuidedMissionRequest["guidedWindowsIdentity"]>["operation"]
        : undefined;
      if (!operation) issues.push("guidedWindowsIdentity.operation is not a reviewed Windows/identity operation");
      const authenticationMode = selection.authenticationMode === "anonymous"
        || selection.authenticationMode === "credential_reference"
        ? selection.authenticationMode
        : undefined;
      if (!authenticationMode) {
        issues.push("guidedWindowsIdentity.authenticationMode must be anonymous or credential_reference");
      }
      let credentialReference: NonNullable<GuidedMissionRequest["guidedWindowsIdentity"]>["credentialReference"] = null;
      if (authenticationMode === "credential_reference") {
        if (!isRecord(selection.credentialReference)
          || selection.credentialReference.kind !== "systemd_credential_bundle"
          || typeof selection.credentialReference.id !== "string"
          || Object.keys(selection.credentialReference).sort().join("\u0000") !== "id\u0000kind"
          || !/^[A-Za-z0-9._:@/-]{1,200}$/u.test(selection.credentialReference.id)) {
          issues.push("guidedWindowsIdentity.credentialReference must be one opaque systemd_credential_bundle reference without credential material or extra fields");
        } else {
          credentialReference = {
            kind: "systemd_credential_bundle",
            id: selection.credentialReference.id,
          };
        }
      } else if (selection.credentialReference !== null && selection.credentialReference !== undefined) {
        issues.push("guidedWindowsIdentity.credentialReference must be null for anonymous reads");
      }
      if (operation && authenticationMode) {
        if (operation === "smb_identity_summary" && authenticationMode !== "credential_reference") {
          issues.push("smb_identity_summary requires an opaque credential reference");
        } else if (operation === "ldap_root_dse" && authenticationMode !== "anonymous") {
          issues.push("ldap_root_dse is currently approved only for anonymous root-directory metadata reads");
        } else {
          guidedWindowsIdentity = { operation, authenticationMode, credentialReference };
        }
      }
    }
  }
  if (guidedWindowsIdentity && (!target || (
    isIP(target) === 0
    && !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/u.test(target)
  ))) {
    issues.push("guidedWindowsIdentity requires target to be one IP address or hostname without a scheme, port, CIDR, or range");
  }
  if (guidedWindowsIdentity && guidedReconnaissance.selection) {
    issues.push("choose either guidedReconnaissance or guidedWindowsIdentity for the first represented Guided step, not both");
  }

  return {
    journey: "guided",
    launch: true,
    authorizationConfirmed: true,
    title: requiredText(root.title, "title", issues, MAX_TITLE_LENGTH),
    objective: requiredText(root.objective, "objective", issues, MAX_OBJECTIVE_LENGTH),
    target,
    engagementId: optionalText(root.engagementId, "engagementId", issues, 240),
    explanationDepth:
      explanationDepth === "concise" || explanationDepth === "deep"
        ? explanationDepth
        : "balanced",
    executionPreference:
      executionPreference === "single_step_agent" ? "single_step_agent" : "manual",
    evidenceExpectations: stringList(
      root.evidenceExpectations,
      "evidenceExpectations",
      issues,
    ),
    ...(guidedReconnaissance.selection ? { guidedReconnaissance: guidedReconnaissance.selection } : {}),
    ...(guidedWindowsIdentity ? { guidedWindowsIdentity } : {}),
  };
}

function validateMissionRequest(
  value: unknown,
  options: {
    readonly allowEmptyAutonomousActionClasses: boolean;
    readonly allowLegacyUnsignedAgentModels?: boolean;
  },
): MissionCreateRequest {
  const issues: string[] = [];
  if (!isRecord(value)) throw new MissionValidationError(["request body must be an object"]);
  if (value.launch !== true) issues.push("launch must be true");
  if (value.journey !== "autonomous" && value.journey !== "guided") {
    throw new MissionValidationError([
      "journey must be exactly autonomous or guided; internal runtime/provider modes are not journeys",
    ]);
  }

  const result =
    value.journey === "autonomous"
        ? parseAutonomous(value, issues, {
            allowEmptyActionClasses: options.allowEmptyAutonomousActionClasses,
            allowLegacyUnsignedAgentModels:
              options.allowLegacyUnsignedAgentModels ?? false,
          })
      : parseGuided(value, issues);
  if (issues.length > 0) throw new MissionValidationError([...new Set(issues)]);
  return result;
}

export function validateMissionCreateRequest(value: unknown): MissionCreateRequest {
  return validateMissionRequest(value, { allowEmptyAutonomousActionClasses: false });
}

/**
 * Preflight accepts a capability-empty draft so the server can return a
 * structured blocked review. The actual create boundary remains strict.
 */
export function validateMissionPreflightRequest(value: unknown): MissionCreateRequest {
  return validateMissionRequest(value, { allowEmptyAutonomousActionClasses: true });
}

/**
 * Read-only compatibility parser for pre-v2.4 contracts. It never authorizes
 * launch: the missing assignment set is represented as empty so branch
 * preflight can explain that a reviewed amendment is required.
 */
export function validateLegacyAutonomousMissionRequest(
  value: unknown,
): AutonomousMissionRequest {
  const request = validateMissionRequest(value, {
    allowEmptyAutonomousActionClasses: true,
    allowLegacyUnsignedAgentModels: true,
  });
  if (request.journey !== "autonomous") {
    throw new MissionValidationError(["legacy contract must be autonomous"]);
  }
  return request;
}

export function validateIdempotencyKey(value: unknown): string {
  if (typeof value !== "string") {
    throw new MissionValidationError(["Idempotency-Key header is required"]);
  }
  const key = value.trim();
  if (key.length < 8 || key.length > 200 || /[\u0000-\u001f\u007f]/u.test(key)) {
    throw new MissionValidationError([
      "Idempotency-Key must contain between 8 and 200 printable characters",
    ]);
  }
  return key;
}

import type {
  PlanChangeApplyResponse,
  PlanChangeDetailResponse,
  PlanChangeDiffEntry,
  PlanChangeJson,
  PlanChangeListResponse,
  PlanChangeOperation,
  PlanChangeRequest,
  PlanStepRepresentationInput,
} from "../types/planChanges";

type UnknownRecord = Record<string, unknown>;
const STATUSES = new Set(["proposed", "validated", "rejected", "applied", "cancelled"]);
const DIFF_KINDS = new Set(["add", "remove", "replace", "move"]);
const OPERATION_KINDS = new Set(["update_plan", "update_step", "add_step", "remove_step", "reorder_steps", "set_dependencies", "set_represented_action"]);
const ACTION_KINDS = new Set(["tool", "provider_turn", "replan", "delegation", "manual"]);
const RISK_CLASSES = new Set(["low", "medium", "high", "critical"]);

function record(value: unknown, label: string): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as UnknownRecord;
}

function exact(value: unknown, label: string, fields: readonly string[]): UnknownRecord {
  const item = record(value, label);
  for (const field of fields) if (!Object.prototype.hasOwnProperty.call(item, field)) throw new Error(`${label} is missing ${field}`);
  for (const key of Object.keys(item)) if (!fields.includes(key)) throw new Error(`${label} contains unsupported field ${key}`);
  return item;
}

function shape(value: unknown, label: string, required: readonly string[], optional: readonly string[] = []): UnknownRecord {
  const item = record(value, label);
  for (const field of required) if (!Object.prototype.hasOwnProperty.call(item, field)) throw new Error(`${label} is missing ${field}`);
  const supported = new Set([...required, ...optional]);
  for (const key of Object.keys(item)) if (!supported.has(key)) throw new Error(`${label} contains unsupported field ${key}`);
  return item;
}

function has(item: UnknownRecord, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(item, field);
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function nullableText(value: unknown, label: string): string | null { return value === null ? null : text(value, label); }
function bool(value: unknown, label: string): boolean { if (typeof value !== "boolean") throw new Error(`${label} must be boolean`); return value; }
function integer(value: unknown, label: string, allowZero = false): number { if (typeof value !== "number" || !Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) throw new Error(`${label} must be ${allowZero ? "non-negative" : "positive"}`); return value; }
function list(value: unknown, label: string): unknown[] { if (!Array.isArray(value)) throw new Error(`${label} must be an array`); return value; }
function texts(value: unknown, label: string): readonly string[] { return list(value, label).map((entry, index) => text(entry, `${label}[${index}]`)); }
function enumeration<T extends string>(value: unknown, values: ReadonlySet<string>, label: string): T { const result = text(value, label); if (!values.has(result)) throw new Error(`${label} is invalid`); return result as T; }
function timestamp(value: unknown, label: string): string { const result = text(value, label); if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO timestamp`); return result; }
function nullableTimestamp(value: unknown, label: string): string | null { return value === null ? null : timestamp(value, label); }

function json(value: unknown, label: string, seen = new Set<object>()): PlanChangeJson {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (!value || typeof value !== "object" || seen.has(value)) throw new Error(`${label} is not safe JSON`);
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map((entry, index) => json(entry, `${label}[${index}]`, seen));
    return Object.fromEntries(Object.entries(value as UnknownRecord).map(([key, entry]) => [key, json(entry, `${label}.${key}`, seen)]));
  } finally { seen.delete(value); }
}

function representation(value: unknown, label: string): PlanStepRepresentationInput {
  const item = exact(value, label, ["action", "explanation", "rationale", "reversibility"]);
  const action = exact(item.action, `${label}.action`, ["actionType", "target", "arguments", "intentSummary", "kind", "idempotent", "destructive"]);
  const argumentsValue = json(action.arguments, `${label}.action.arguments`);
  if (!argumentsValue || typeof argumentsValue !== "object" || Array.isArray(argumentsValue)) {
    throw new Error(`${label}.action.arguments must be an object`);
  }
  return {
    action: {
      actionType: text(action.actionType, `${label}.action.actionType`),
      target: text(action.target, `${label}.action.target`),
      arguments: argumentsValue as Readonly<Record<string, PlanChangeJson>>,
      intentSummary: text(action.intentSummary, `${label}.action.intentSummary`),
      kind: enumeration(action.kind, ACTION_KINDS, `${label}.action.kind`),
      idempotent: bool(action.idempotent, `${label}.action.idempotent`),
      destructive: bool(action.destructive, `${label}.action.destructive`),
    },
    explanation: text(item.explanation, `${label}.explanation`),
    rationale: text(item.rationale, `${label}.rationale`),
    reversibility: text(item.reversibility, `${label}.reversibility`),
  };
}

function operation(value: unknown, index: number): PlanChangeOperation {
  const label = `operation[${index}]`;
  const root = record(value, label);
  const kind = enumeration<PlanChangeOperation["kind"]>(root.kind, OPERATION_KINDS, `${label}.kind`);
  if (kind === "update_plan") {
    const item = shape(root, label, ["kind"], ["strategySummary", "rationaleSummary"]);
    if (!has(item, "strategySummary") && !has(item, "rationaleSummary")) throw new Error(`${label} must change at least one plan field`);
    return {
      kind,
      ...(has(item, "strategySummary") ? { strategySummary: text(item.strategySummary, `${label}.strategySummary`) } : {}),
      ...(has(item, "rationaleSummary") ? { rationaleSummary: nullableText(item.rationaleSummary, `${label}.rationaleSummary`) } : {}),
    };
  }
  if (kind === "update_step") {
    const optional = ["phase", "title", "objective", "successCriteria", "actionClass", "riskClass", "assignedAgentId"];
    const item = shape(root, label, ["kind", "stepId"], optional);
    if (!optional.some((field) => has(item, field))) throw new Error(`${label} must change at least one step field`);
    return {
      kind,
      stepId: text(item.stepId, `${label}.stepId`),
      ...(has(item, "phase") ? { phase: text(item.phase, `${label}.phase`) } : {}),
      ...(has(item, "title") ? { title: text(item.title, `${label}.title`) } : {}),
      ...(has(item, "objective") ? { objective: text(item.objective, `${label}.objective`) } : {}),
      ...(has(item, "successCriteria") ? { successCriteria: texts(item.successCriteria, `${label}.successCriteria`) } : {}),
      ...(has(item, "actionClass") ? { actionClass: nullableText(item.actionClass, `${label}.actionClass`) } : {}),
      ...(has(item, "riskClass") ? { riskClass: nullableText(item.riskClass, `${label}.riskClass`) } : {}),
      ...(has(item, "assignedAgentId") ? { assignedAgentId: nullableText(item.assignedAgentId, `${label}.assignedAgentId`) } : {}),
    };
  }
  if (kind === "add_step") {
    const item = shape(root, label, ["kind", "clientStepId", "phase", "title", "objective", "successCriteria", "dependencyStepIds", "actionClass", "riskClass", "assignedAgentId", "representation"], ["afterStepId"]);
    const riskClass = enumeration<"low" | "medium" | "high" | "critical">(item.riskClass, RISK_CLASSES, `${label}.riskClass`);
    const successCriteria = texts(item.successCriteria, `${label}.successCriteria`);
    if (successCriteria.length === 0) throw new Error(`${label}.successCriteria must not be empty`);
    return {
      kind,
      clientStepId: text(item.clientStepId, `${label}.clientStepId`),
      ...(has(item, "afterStepId") ? { afterStepId: nullableText(item.afterStepId, `${label}.afterStepId`) } : {}),
      phase: text(item.phase, `${label}.phase`),
      title: text(item.title, `${label}.title`),
      objective: text(item.objective, `${label}.objective`),
      successCriteria,
      dependencyStepIds: texts(item.dependencyStepIds, `${label}.dependencyStepIds`),
      actionClass: text(item.actionClass, `${label}.actionClass`),
      riskClass,
      assignedAgentId: text(item.assignedAgentId, `${label}.assignedAgentId`),
      representation: representation(item.representation, `${label}.representation`),
    };
  }
  if (kind === "remove_step") {
    const item = exact(root, label, ["kind", "stepId", "reason"]);
    return { kind, stepId: text(item.stepId, `${label}.stepId`), reason: text(item.reason, `${label}.reason`) };
  }
  if (kind === "reorder_steps") {
    const item = exact(root, label, ["kind", "orderedStepIds"]);
    const orderedStepIds = texts(item.orderedStepIds, `${label}.orderedStepIds`);
    if (orderedStepIds.length === 0) throw new Error(`${label}.orderedStepIds must not be empty`);
    return { kind, orderedStepIds };
  }
  if (kind === "set_dependencies") {
    const item = exact(root, label, ["kind", "stepId", "dependencyStepIds"]);
    return { kind, stepId: text(item.stepId, `${label}.stepId`), dependencyStepIds: texts(item.dependencyStepIds, `${label}.dependencyStepIds`) };
  }
  const item = exact(root, label, ["kind", "stepId", "representation"]);
  return { kind, stepId: text(item.stepId, `${label}.stepId`), representation: representation(item.representation, `${label}.representation`) };
}

function diffEntry(value: unknown, index: number): PlanChangeDiffEntry {
  const item = exact(value, `plan diff[${index}]`, ["kind", "path", "label", "before", "after"]);
  return { kind: enumeration(item.kind, DIFF_KINDS, "diff kind"), path: text(item.path, "diff path"), label: text(item.label, "diff label"), before: json(item.before, "diff before"), after: json(item.after, "diff after") };
}

export function parsePlanChangeRequest(value: unknown): PlanChangeRequest {
  const fields = ["id", "missionId", "runId", "basePlanId", "basePlanVersion", "requestedBy", "requestText", "normalizedChange", "structuredDiff", "affectedRefs", "dependencyImpact", "policyValidation", "readinessImpact", "budgetImpact", "inflightImpact", "status", "resultPlanId", "createdAt", "resolvedAt", "version"];
  const item = exact(value, "plan change request", fields);
  const normalized = exact(item.normalizedChange, "normalized change", ["summary", "operations"]);
  const affected = exact(item.affectedRefs, "affected refs", ["stepIds", "addedClientStepIds", "removedStepIds", "agentIds", "actionClasses"]);
  const dependency = exact(item.dependencyImpact, "dependency impact", ["valid", "changed", "reordered", "issues"]);
  const policy = exact(item.policyValidation, "policy validation", ["valid", "journey", "contractId", "checkedActionClasses", "prohibitedActionClasses", "reasons"]);
  const readiness = exact(item.readinessImpact, "readiness impact", ["valid", "checkedAgentIds", "unavailableAgentIds", "reasons"]);
  const budget = exact(item.budgetImpact, "budget impact", ["addedSteps", "removedSteps", "netStepChange", "durationEstimate", "costEstimate", "explanation"]);
  const inflight = exact(item.inflightImpact, "inflight impact", ["safeToApply", "runStatus", "leaseOwner", "activeStepIds", "activeAssignmentIds", "activeActionIds", "pendingDecisionIds", "queuedAssignmentIdsToCancel", "requiresCheckpoint", "requiresCancellation", "reasons"]);
  const normalizedOperations = list(normalized.operations, "normalized operations");
  if (normalizedOperations.length < 1 || normalizedOperations.length > 50) throw new Error("normalized operations must contain 1 through 50 entries");
  if (budget.durationEstimate !== "not_observed" || budget.costEstimate !== "not_observed") throw new Error("unmeasured plan impact must remain not_observed");
  return {
    id: text(item.id, "request ID"), missionId: text(item.missionId, "mission ID"), runId: text(item.runId, "run ID"), basePlanId: text(item.basePlanId, "base plan ID"), basePlanVersion: integer(item.basePlanVersion, "base plan version"), requestedBy: text(item.requestedBy, "requested by"), requestText: nullableText(item.requestText, "request text"),
    normalizedChange: { summary: text(normalized.summary, "normalized summary"), operations: normalizedOperations.map(operation) },
    structuredDiff: list(item.structuredDiff, "structured diff").map(diffEntry),
    affectedRefs: { stepIds: texts(affected.stepIds, "affected steps"), addedClientStepIds: texts(affected.addedClientStepIds, "added steps"), removedStepIds: texts(affected.removedStepIds, "removed steps"), agentIds: texts(affected.agentIds, "affected agents"), actionClasses: texts(affected.actionClasses, "affected action classes") },
    dependencyImpact: { valid: bool(dependency.valid, "dependency validity"), changed: bool(dependency.changed, "dependency changed"), reordered: bool(dependency.reordered, "dependency reordered"), issues: texts(dependency.issues, "dependency issues") },
    policyValidation: { valid: bool(policy.valid, "policy validity"), journey: enumeration(policy.journey, new Set(["autonomous", "guided"]), "policy journey"), contractId: nullableText(policy.contractId, "contract ID"), checkedActionClasses: texts(policy.checkedActionClasses, "checked action classes"), prohibitedActionClasses: texts(policy.prohibitedActionClasses, "prohibited action classes"), reasons: texts(policy.reasons, "policy reasons") },
    readinessImpact: { valid: bool(readiness.valid, "readiness validity"), checkedAgentIds: texts(readiness.checkedAgentIds, "checked agents"), unavailableAgentIds: texts(readiness.unavailableAgentIds, "unavailable agents"), reasons: texts(readiness.reasons, "readiness reasons") },
    budgetImpact: { addedSteps: integer(budget.addedSteps, "added steps", true), removedSteps: integer(budget.removedSteps, "removed steps", true), netStepChange: typeof budget.netStepChange === "number" && Number.isSafeInteger(budget.netStepChange) ? budget.netStepChange : (() => { throw new Error("net step change must be an integer"); })(), durationEstimate: "not_observed", costEstimate: "not_observed", explanation: text(budget.explanation, "budget explanation") },
    inflightImpact: { safeToApply: bool(inflight.safeToApply, "safe to apply"), runStatus: text(inflight.runStatus, "run status"), leaseOwner: nullableText(inflight.leaseOwner, "lease owner"), activeStepIds: texts(inflight.activeStepIds, "active steps"), activeAssignmentIds: texts(inflight.activeAssignmentIds, "active assignments"), activeActionIds: texts(inflight.activeActionIds, "active actions"), pendingDecisionIds: texts(inflight.pendingDecisionIds, "pending decisions"), queuedAssignmentIdsToCancel: texts(inflight.queuedAssignmentIdsToCancel, "queued assignments"), requiresCheckpoint: bool(inflight.requiresCheckpoint, "requires checkpoint"), requiresCancellation: bool(inflight.requiresCancellation, "requires cancellation"), reasons: texts(inflight.reasons, "inflight reasons") },
    status: enumeration(item.status, STATUSES, "plan change status"), resultPlanId: nullableText(item.resultPlanId, "result plan ID"), createdAt: timestamp(item.createdAt, "created time"), resolvedAt: nullableTimestamp(item.resolvedAt, "resolved time"), version: integer(item.version, "request version"),
  };
}

function schemaVersion(value: unknown): "2.4" { if (value !== "2.4") throw new Error("unsupported Ti-Scale schema version"); return "2.4"; }

export function parsePlanChangeList(payload: unknown): PlanChangeListResponse {
  const item = exact(payload, "plan change list", ["schemaVersion", "items"]);
  return { schemaVersion: schemaVersion(item.schemaVersion), items: list(item.items, "plan changes").map(parsePlanChangeRequest) };
}

export function parsePlanChangeDetail(payload: unknown): PlanChangeDetailResponse {
  const item = shape(payload, "plan change detail", ["schemaVersion", "request"], ["contextPackId"]);
  return {
    schemaVersion: schemaVersion(item.schemaVersion),
    request: parsePlanChangeRequest(item.request),
    contextPackId: has(item, "contextPackId") ? nullableText(item.contextPackId, "context pack ID") : null,
  };
}

export function parsePlanChangeApply(payload: unknown): PlanChangeApplyResponse {
  const item = shape(payload, "plan change apply", ["schemaVersion", "request", "resultPlanId", "resultPlanVersion"], ["contextPackId"]);
  return {
    schemaVersion: schemaVersion(item.schemaVersion),
    request: parsePlanChangeRequest(item.request),
    resultPlanId: text(item.resultPlanId, "result plan ID"),
    resultPlanVersion: integer(item.resultPlanVersion, "result plan version"),
    contextPackId: has(item, "contextPackId") ? nullableText(item.contextPackId, "context pack ID") : null,
  };
}

import { ACTION_CLASS_IDS } from "../domain/catalog-ids";
import type {
  ApplyPlanChangeInput,
  CreatePlanChangeInput,
  EditPlanChangeInput,
  PlanChangeJson,
  PlanChangeOperation,
  PlanStepRepresentationInput,
  RejectPlanChangeInput,
} from "./types";
import { PlanChangeError } from "./types";

type UnknownRecord = Record<string, unknown>;

const ACTION_CLASSES = new Set<string>(ACTION_CLASS_IDS);
const ACTION_KINDS = new Set(["tool", "provider_turn", "replan", "delegation", "manual"]);
const RISK_CLASSES = new Set(["low", "medium", "high", "critical"]);
const SENSITIVE_TEXT = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]|\bbearer\s+[a-z0-9._~+\/-]{16,})/iu;
const SENSITIVE_ARGUMENT_KEY = /^(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key|session[_-]?token)$/iu;

function object(value: unknown, label: string): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${label} must be an object`);
  }
  return value as UnknownRecord;
}

function exact(value: unknown, label: string, required: readonly string[], optional: readonly string[] = []): UnknownRecord {
  const item = object(value, label);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(item)) if (!allowed.has(key)) throw invalid(`${label} contains unsupported field ${key}`);
  for (const key of required) if (!Object.prototype.hasOwnProperty.call(item, key)) throw invalid(`${label} is missing ${key}`);
  return item;
}

function invalid(message: string): PlanChangeError {
  return new PlanChangeError("invalid_plan_change_request", message, "invalid_input", 400, "Correct the structured amendment and resubmit it against the current run and plan versions.");
}

export function identifier(value: unknown, label: string): string {
  if (typeof value !== "string") throw invalid(`${label} must be a string`);
  const result = value.trim();
  if (!result || result.length > 200 || /[\u0000-\u001f\u007f]/u.test(result)) throw invalid(`${label} is invalid`);
  return result;
}

function boundedText(value: unknown, label: string, maximum = 2_000): string {
  if (typeof value !== "string") throw invalid(`${label} must be a string`);
  const result = value.trim();
  if (!result || result.length > maximum || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(result)) {
    throw invalid(`${label} must contain 1 through ${maximum} printable characters`);
  }
  if (SENSITIVE_TEXT.test(result)) {
    throw new PlanChangeError(
      "sensitive_plan_change_text",
      `${label} appears to contain authentication material and was not stored`,
      "sensitive_data",
      400,
      "Remove credentials, tokens, private keys, and secret values. Refer to an approved secret by stable identifier instead.",
    );
  }
  return result;
}

function optionalText(value: unknown, label: string, maximum = 2_000): string | undefined {
  return value === undefined ? undefined : boundedText(value, label, maximum);
}

function nullableText(value: unknown, label: string): string | null {
  return value === null ? null : boundedText(value, label);
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw invalid(`${label} must be a positive integer`);
  return value;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw invalid(`${label} must be boolean`);
  return value;
}

function stringList(value: unknown, label: string, maximum = 40): readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) throw invalid(`${label} must be an array with at most ${maximum} entries`);
  const result = value.map((entry, index) => boundedText(entry, `${label}[${index}]`, 500));
  if (new Set(result).size !== result.length) throw invalid(`${label} cannot contain duplicates`);
  return result;
}

function optionalIdentifier(value: unknown, label: string): string | null | undefined {
  return value === undefined ? undefined : value === null ? null : identifier(value, label);
}

function optionalActionClass(value: unknown): string | null | undefined {
  if (value === undefined || value === null) return value;
  const result = identifier(value, "actionClass");
  if (!ACTION_CLASSES.has(result)) throw invalid(`actionClass is not present in the canonical ActionClassRegistry: ${result}`);
  return result;
}

function jsonArgumentValue(
  value: unknown,
  label: string,
  state: { count: number },
  depth = 0,
): PlanChangeJson {
  state.count += 1;
  if (state.count > 500) throw invalid(`${label} exceeds the 500-value argument limit`);
  if (depth > 8) throw invalid(`${label} exceeds the maximum nesting depth`);
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw invalid(`${label} must contain finite numbers`);
    return value;
  }
  if (typeof value === "string") {
    if (value.length > 4_000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
      throw invalid(`${label} strings must contain at most 4000 printable characters`);
    }
    if (SENSITIVE_TEXT.test(value)) {
      throw new PlanChangeError(
        "sensitive_plan_change_argument",
        `${label} appears to contain authentication material and was not stored`,
        "sensitive_data",
        400,
        "Replace credentials with an approved opaque credential reference before proposing the action.",
      );
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 100) throw invalid(`${label} arrays may contain at most 100 values`);
    return value.map((entry, index) => jsonArgumentValue(entry, `${label}[${index}]`, state, depth + 1));
  }
  const item = object(value, label);
  const entries = Object.entries(item);
  if (entries.length > 100) throw invalid(`${label} objects may contain at most 100 fields`);
  return Object.fromEntries(entries.map(([key, entry]) => {
    if (!key || key.length > 200 || /[\u0000-\u001f\u007f]/u.test(key)) throw invalid(`${label} contains an invalid field name`);
    if (SENSITIVE_ARGUMENT_KEY.test(key)) {
      throw new PlanChangeError(
        "sensitive_plan_change_argument",
        `${label}.${key} is a secret-bearing field and was not stored`,
        "sensitive_data",
        400,
        "Use a non-secret credentialRef or approved secret identifier instead of embedding authentication material.",
      );
    }
    return [key, jsonArgumentValue(entry, `${label}.${key}`, state, depth + 1)];
  }));
}

function representation(value: unknown, label: string): PlanStepRepresentationInput {
  const root = exact(value, label, ["action", "explanation", "rationale", "reversibility"]);
  const action = exact(root.action, `${label}.action`, ["actionType", "target", "arguments", "intentSummary", "kind", "idempotent", "destructive"]);
  const actionType = boundedText(action.actionType, `${label}.action.actionType`, 120).toLowerCase();
  const kind = identifier(action.kind, `${label}.action.kind`);
  if (!ACTION_KINDS.has(kind)) throw invalid(`${label}.action.kind is invalid`);
  const argumentsValue = jsonArgumentValue(action.arguments, `${label}.action.arguments`, { count: 0 });
  if (!argumentsValue || typeof argumentsValue !== "object" || Array.isArray(argumentsValue)) {
    throw invalid(`${label}.action.arguments must be an object`);
  }
  return {
    action: {
      actionType,
      target: boundedText(action.target, `${label}.action.target`, 2_000),
      arguments: argumentsValue as Readonly<Record<string, PlanChangeJson>>,
      intentSummary: boundedText(action.intentSummary, `${label}.action.intentSummary`, 1_000),
      kind: kind as PlanStepRepresentationInput["action"]["kind"],
      idempotent: booleanValue(action.idempotent, `${label}.action.idempotent`),
      destructive: booleanValue(action.destructive, `${label}.action.destructive`),
    },
    explanation: boundedText(root.explanation, `${label}.explanation`, 2_000),
    rationale: boundedText(root.rationale, `${label}.rationale`, 2_000),
    reversibility: boundedText(root.reversibility, `${label}.reversibility`, 2_000),
  };
}

function parseOperation(value: unknown, index: number): PlanChangeOperation {
  const root = object(value, `operations[${index}]`);
  const kind = root.kind;
  if (kind === "update_plan") {
    const item = exact(root, `operations[${index}]`, ["kind"], ["strategySummary", "rationaleSummary"]);
    const strategySummary = optionalText(item.strategySummary, "strategySummary");
    const rationaleSummary = item.rationaleSummary === undefined ? undefined : nullableText(item.rationaleSummary, "rationaleSummary");
    if (strategySummary === undefined && rationaleSummary === undefined) throw invalid("update_plan must change at least one field");
    return { kind, ...(strategySummary === undefined ? {} : { strategySummary }), ...(rationaleSummary === undefined ? {} : { rationaleSummary }) };
  }
  if (kind === "update_step") {
    const item = exact(root, `operations[${index}]`, ["kind", "stepId"], ["phase", "title", "objective", "successCriteria", "actionClass", "riskClass", "assignedAgentId"]);
    const stepId = identifier(item.stepId, "stepId");
    const phase = optionalText(item.phase, "phase", 200);
    const title = optionalText(item.title, "title", 500);
    const objective = optionalText(item.objective, "objective");
    const successCriteria = item.successCriteria === undefined ? undefined : stringList(item.successCriteria, "successCriteria");
    const actionClass = optionalActionClass(item.actionClass);
    const riskClass = item.riskClass === undefined ? undefined : item.riskClass === null ? null : boundedText(item.riskClass, "riskClass", 100);
    const assignedAgentId = optionalIdentifier(item.assignedAgentId, "assignedAgentId");
    if ([phase, title, objective, successCriteria, actionClass, riskClass, assignedAgentId].every((entry) => entry === undefined)) {
      throw invalid("update_step must change at least one field");
    }
    return { kind, stepId, ...(phase === undefined ? {} : { phase }), ...(title === undefined ? {} : { title }), ...(objective === undefined ? {} : { objective }), ...(successCriteria === undefined ? {} : { successCriteria }), ...(actionClass === undefined ? {} : { actionClass }), ...(riskClass === undefined ? {} : { riskClass }), ...(assignedAgentId === undefined ? {} : { assignedAgentId }) };
  }
  if (kind === "add_step") {
    const item = exact(root, `operations[${index}]`, ["kind", "clientStepId", "phase", "title", "objective", "successCriteria", "dependencyStepIds", "actionClass", "riskClass", "assignedAgentId", "representation"], ["afterStepId"]);
    const clientStepId = identifier(item.clientStepId, "clientStepId");
    if (!/^draft-[a-z0-9][a-z0-9._-]{0,79}$/u.test(clientStepId)) throw invalid("clientStepId must use the draft- namespace");
    const actionClass = optionalActionClass(item.actionClass);
    if (!actionClass) throw invalid("add_step.actionClass is required");
    const riskClass = identifier(item.riskClass, "riskClass");
    if (!RISK_CLASSES.has(riskClass)) throw invalid("riskClass must be low, medium, high, or critical");
    return {
      kind,
      clientStepId,
      ...(item.afterStepId === undefined ? {} : { afterStepId: optionalIdentifier(item.afterStepId, "afterStepId") }),
      phase: boundedText(item.phase, "phase", 200),
      title: boundedText(item.title, "title", 500),
      objective: boundedText(item.objective, "objective"),
      successCriteria: stringList(item.successCriteria, "successCriteria"),
      dependencyStepIds: stringList(item.dependencyStepIds, "dependencyStepIds").map((entry) => identifier(entry, "dependencyStepId")),
      actionClass,
      riskClass: riskClass as "low" | "medium" | "high" | "critical",
      assignedAgentId: identifier(item.assignedAgentId, "assignedAgentId"),
      representation: representation(item.representation, `operations[${index}].representation`),
    };
  }
  if (kind === "remove_step") {
    const item = exact(root, `operations[${index}]`, ["kind", "stepId", "reason"]);
    return { kind, stepId: identifier(item.stepId, "stepId"), reason: boundedText(item.reason, "reason", 1_000) };
  }
  if (kind === "reorder_steps") {
    const item = exact(root, `operations[${index}]`, ["kind", "orderedStepIds"]);
    return { kind, orderedStepIds: stringList(item.orderedStepIds, "orderedStepIds", 200).map((entry) => identifier(entry, "orderedStepId")) };
  }
  if (kind === "set_dependencies") {
    const item = exact(root, `operations[${index}]`, ["kind", "stepId", "dependencyStepIds"]);
    return { kind, stepId: identifier(item.stepId, "stepId"), dependencyStepIds: stringList(item.dependencyStepIds, "dependencyStepIds", 100).map((entry) => identifier(entry, "dependencyStepId")) };
  }
  if (kind === "set_represented_action") {
    const item = exact(root, `operations[${index}]`, ["kind", "stepId", "representation"]);
    return {
      kind,
      stepId: identifier(item.stepId, "stepId"),
      representation: representation(item.representation, `operations[${index}].representation`),
    };
  }
  throw invalid(`operations[${index}].kind is unsupported`);
}

function operations(value: unknown): readonly PlanChangeOperation[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 50) throw invalid("operations must contain 1 through 50 structured changes");
  return value.map(parseOperation);
}

export function parseCreatePlanChangeInput(missionId: string, runId: string, value: unknown): CreatePlanChangeInput {
  const item = exact(value, "plan change proposal", ["basePlanId", "expectedRunVersion", "expectedPlanVersion", "operations"], ["requestText"]);
  return {
    missionId,
    runId,
    basePlanId: identifier(item.basePlanId, "basePlanId"),
    expectedRunVersion: positiveInteger(item.expectedRunVersion, "expectedRunVersion"),
    expectedPlanVersion: positiveInteger(item.expectedPlanVersion, "expectedPlanVersion"),
    ...(item.requestText === undefined ? {} : { requestText: boundedText(item.requestText, "requestText", 4_000) }),
    operations: operations(item.operations),
  };
}

export function parseEditPlanChangeInput(requestId: string, value: unknown): EditPlanChangeInput {
  const item = exact(value, "plan change edit", ["expectedRequestVersion", "expectedRunVersion", "expectedPlanVersion", "operations"], ["requestText"]);
  return {
    requestId,
    expectedRequestVersion: positiveInteger(item.expectedRequestVersion, "expectedRequestVersion"),
    expectedRunVersion: positiveInteger(item.expectedRunVersion, "expectedRunVersion"),
    expectedPlanVersion: positiveInteger(item.expectedPlanVersion, "expectedPlanVersion"),
    ...(item.requestText === undefined ? {} : { requestText: boundedText(item.requestText, "requestText", 4_000) }),
    operations: operations(item.operations),
  };
}

export function parseApplyPlanChangeInput(requestId: string, value: unknown): ApplyPlanChangeInput {
  const item = exact(value, "plan change apply", ["expectedRequestVersion", "expectedRunVersion", "expectedPlanVersion"]);
  return {
    requestId,
    expectedRequestVersion: positiveInteger(item.expectedRequestVersion, "expectedRequestVersion"),
    expectedRunVersion: positiveInteger(item.expectedRunVersion, "expectedRunVersion"),
    expectedPlanVersion: positiveInteger(item.expectedPlanVersion, "expectedPlanVersion"),
  };
}

export function parseRejectPlanChangeInput(requestId: string, value: unknown): RejectPlanChangeInput {
  const item = exact(value, "plan change rejection", ["expectedRequestVersion", "reason"]);
  return {
    requestId,
    expectedRequestVersion: positiveInteger(item.expectedRequestVersion, "expectedRequestVersion"),
    reason: boundedText(item.reason, "reason", 2_000),
  };
}

export function requiredIdempotencyKey(value: string | undefined): string {
  if (!value) throw new PlanChangeError("plan_change_idempotency_key_required", "Idempotency-Key is required", "invalid_input", 400, "Retry with one stable Idempotency-Key for this exact mutation.");
  const key = value.trim();
  if (key.length < 8 || key.length > 200 || /[^A-Za-z0-9._:-]/u.test(key)) throw invalid("Idempotency-Key is invalid");
  return key;
}

import type {
  EngagementLogDetailV24,
  EngagementLogRecordV24,
  EvidenceCandidateDetailV24,
  EvidenceCandidateMutationV24,
  EvidenceCandidateStateV24,
  EvidenceCandidateV24,
  EvidenceCustodyEventV24,
  FailureCategoryV24,
  FailureDiagnosisDetailV24,
  FailureDiagnosisListV24,
  FailureDiagnosisMutationV24,
  FailureDiagnosisStateV24,
  FailureDiagnosisV24,
  FailureOperatorActionKindV24,
  ObservationDetailV24,
  ObservationV24,
  OperationalJsonValue,
  OperationalSensitivity,
  OperationalTruthPage,
  VerifiedEvidenceDetailV24,
  VerifiedEvidenceMutationV24,
  VerifiedEvidenceV24,
} from "../types/operationalTruth";
import { FAILURE_CATEGORIES_V24 } from "../types/operationalTruth";
import { array, boolean, nonEmpty, number, object, schema, string } from "./common";

type Parser<T> = (value: unknown) => T;

const IDENTIFIER = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SENSITIVITIES = new Set<OperationalSensitivity>(["public", "internal", "private", "restricted"]);
const LOG_SEVERITIES = new Set<EngagementLogRecordV24["severity"]>([
  "debug", "info", "notice", "warning", "error", "critical",
]);
const OBSERVATION_STATES = new Set<ObservationV24["verificationState"]>([
  "unverified", "corroborated", "conflicting", "stale", "rejected",
]);
const CANDIDATE_STATES = new Set<EvidenceCandidateStateV24>([
  "candidate", "validating", "promoted", "rejected", "demoted",
]);
const FAILURE_CATEGORIES = new Set<FailureCategoryV24>(FAILURE_CATEGORIES_V24);
const FAILURE_STATES = new Set<FailureDiagnosisStateV24>(["active", "resolved", "superseded", "terminal"]);
const FAILURE_SUBJECTS = new Set<FailureDiagnosisV24["subjectType"]>([
  "mission", "run", "step", "assignment", "action", "attack_attempt",
]);
const FAILURE_REFERENCE_KINDS = new Set<FailureDiagnosisV24["preservedReferences"][number]["kind"]>([
  "event", "log", "evidence", "artifact", "checkpoint", "finding", "memory",
]);
const FAILURE_ACTION_KINDS = new Set<FailureOperatorActionKindV24>([
  "test_connection", "configure_dependency", "use_compatible_fallback", "retry_bounded",
  "resume_checkpoint", "reassign", "amend_plan", "skip", "start_new_run", "terminate_gracefully",
]);

function enumValue<T extends string>(value: unknown, values: ReadonlySet<T>, label: string): T {
  const result = nonEmpty(value, label) as T;
  if (!values.has(result)) throw new Error(`${label} is invalid`);
  return result;
}

function identifier(value: unknown, label: string): string {
  const result = nonEmpty(value, label);
  if (!IDENTIFIER.test(result)) throw new Error(`${label} must be a stable identifier`);
  return result;
}

function optionalIdentifier(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : identifier(value, label);
}

function optionalText(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : nonEmpty(value, label);
}

function timestamp(value: unknown, label: string): string {
  const result = nonEmpty(value, label);
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO-8601 timestamp`);
  return result;
}

function optionalTimestamp(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : timestamp(value, label);
}

function confidence(value: unknown, label: string): number {
  const result = number(value, label);
  if (result < 0 || result > 1) throw new Error(`${label} must be between zero and one`);
  return result;
}

function contentHash(value: unknown, label: string): string {
  const result = nonEmpty(value, label);
  if (!SHA256.test(result)) throw new Error(`${label} must be a lowercase SHA-256 digest`);
  return result;
}

interface JsonBudget { nodes: number }

function jsonValue(value: unknown, label: string, budget: JsonBudget = { nodes: 0 }, depth = 0): OperationalJsonValue {
  budget.nodes += 1;
  if (budget.nodes > 10_000 || depth > 16) throw new Error(`${label} exceeds the operational JSON bound`);
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} contains a non-finite number`);
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 2_000) throw new Error(`${label} contains too many array items`);
    return value.map((entry, index) => jsonValue(entry, `${label}[${index}]`, budget, depth + 1));
  }
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > 2_000) throw new Error(`${label} contains too many object properties`);
    const result: Record<string, OperationalJsonValue> = {};
    for (const [key, entry] of entries) {
      if (entry === undefined) throw new Error(`${label}.${key} is not JSON-compatible`);
      result[key] = jsonValue(entry, `${label}.${key}`, budget, depth + 1);
    }
    return result;
  }
  throw new Error(`${label} must contain JSON-compatible values only`);
}

function uniqueTextList(value: unknown, label: string): readonly string[] {
  const result = array(value, label).map((entry, index) => nonEmpty(entry, `${label}[${index}]`));
  if (new Set(result).size !== result.length) throw new Error(`${label} contains duplicate values`);
  return result;
}

function optionalIds(item: Record<string, unknown>, fields: readonly string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (const field of fields) {
    const parsed = optionalIdentifier(item[field], field);
    if (parsed !== undefined) result[field] = parsed;
  }
  return result;
}

function page<T>(payload: unknown, label: string, parse: Parser<T>): OperationalTruthPage<T> {
  const root = object(payload, label);
  schema(root);
  const cursor = root.nextCursor;
  if (cursor !== null && typeof cursor !== "string") throw new Error(`${label}.nextCursor must be a string or null`);
  if (typeof cursor === "string" && cursor.length === 0) throw new Error(`${label}.nextCursor cannot be empty`);
  return {
    schemaVersion: "2.4",
    items: array(root.items, `${label}.items`).map(parse),
    nextCursor: cursor,
  };
}

export function parseEngagementLog(value: unknown): EngagementLogRecordV24 {
  const item = object(value, "engagement log");
  return {
    id: identifier(item.id, "engagement log.id"),
    missionId: identifier(item.missionId, "engagement log.missionId"),
    ...optionalIds(item, [
      "runId", "planId", "stepId", "actionId", "attackAttemptId", "assetId", "agentId",
      "providerTurnId", "toolCallId", "traceId", "spanId",
    ]),
    severity: enumValue(item.severity, LOG_SEVERITIES, "engagement log.severity"),
    domain: nonEmpty(item.domain, "engagement log.domain"),
    recordType: nonEmpty(item.recordType, "engagement log.recordType"),
    humanSummary: nonEmpty(item.humanSummary, "engagement log.humanSummary"),
    technicalPayload: jsonValue(item.technicalPayload, "engagement log.technicalPayload"),
    contentHash: contentHash(item.contentHash, "engagement log.contentHash"),
    sensitivity: enumValue(item.sensitivity, SENSITIVITIES, "engagement log.sensitivity"),
    occurredAt: timestamp(item.occurredAt, "engagement log.occurredAt"),
    createdAt: timestamp(item.createdAt, "engagement log.createdAt"),
  };
}

export function parseEngagementLogPage(payload: unknown): OperationalTruthPage<EngagementLogRecordV24> {
  return page(payload, "engagement log page", parseEngagementLog);
}

export function parseEngagementLogDetail(payload: unknown): EngagementLogDetailV24 {
  const root = object(payload, "engagement log detail");
  schema(root);
  return { schemaVersion: "2.4", log: parseEngagementLog(root.log) };
}

export function parseObservation(value: unknown): ObservationV24 {
  const item = object(value, "observation");
  const sources = array(item.sources, "observation.sources").map((value, index) => {
    const source = object(value, `observation.sources[${index}]`);
    return {
      logRecordId: identifier(source.logRecordId, `observation.sources[${index}].logRecordId`),
      parserId: identifier(source.parserId, `observation.sources[${index}].parserId`),
      parserVersion: nonEmpty(source.parserVersion, `observation.sources[${index}].parserVersion`),
    };
  });
  if (sources.length === 0) throw new Error("observation.sources cannot be empty");
  return {
    id: identifier(item.id, "observation.id"),
    missionId: identifier(item.missionId, "observation.missionId"),
    ...optionalIds(item, ["runId", "stepId", "assetId", "sourceAgentId"]),
    ...(optionalText(item.sourceTool, "observation.sourceTool") === undefined
      ? {} : { sourceTool: optionalText(item.sourceTool, "observation.sourceTool") }),
    observationType: nonEmpty(item.observationType, "observation.observationType"),
    statement: nonEmpty(item.statement, "observation.statement"),
    normalizedValue: jsonValue(item.normalizedValue, "observation.normalizedValue"),
    confidence: confidence(item.confidence, "observation.confidence"),
    verificationState: enumValue(item.verificationState, OBSERVATION_STATES, "observation.verificationState"),
    firstSeenAt: timestamp(item.firstSeenAt, "observation.firstSeenAt"),
    lastSeenAt: timestamp(item.lastSeenAt, "observation.lastSeenAt"),
    sensitivity: enumValue(item.sensitivity, SENSITIVITIES, "observation.sensitivity"),
    sources,
    createdAt: timestamp(item.createdAt, "observation.createdAt"),
  };
}

export function parseObservationPage(payload: unknown): OperationalTruthPage<ObservationV24> {
  return page(payload, "observation page", parseObservation);
}

export function parseObservationDetail(payload: unknown): ObservationDetailV24 {
  const root = object(payload, "observation detail");
  schema(root);
  return { schemaVersion: "2.4", observation: parseObservation(root.observation) };
}

export function parseEvidenceCandidate(value: unknown): EvidenceCandidateV24 {
  const item = object(value, "evidence candidate");
  const state = enumValue(item.state, CANDIDATE_STATES, "evidence candidate.state");
  const reviewedBy = optionalIdentifier(item.reviewedBy, "evidence candidate.reviewedBy");
  const reviewReason = optionalText(item.reviewReason, "evidence candidate.reviewReason");
  const reviewedAt = optionalTimestamp(item.reviewedAt, "evidence candidate.reviewedAt");
  const promotedEvidenceId = optionalIdentifier(item.promotedEvidenceId, "evidence candidate.promotedEvidenceId");
  if (state !== "candidate" && (!reviewedBy || !reviewReason || !reviewedAt)) {
    throw new Error("reviewed evidence candidate is missing its review provenance");
  }
  if (state === "promoted" && !promotedEvidenceId) {
    throw new Error("promoted evidence candidate is missing its verified evidence link");
  }
  return {
    id: identifier(item.id, "evidence candidate.id"),
    missionId: identifier(item.missionId, "evidence candidate.missionId"),
    ...optionalIds(item, ["runId", "stepId", "observationId", "artifactId"]),
    evidenceType: nonEmpty(item.evidenceType, "evidence candidate.evidenceType"),
    label: nonEmpty(item.label, "evidence candidate.label"),
    meaning: nonEmpty(item.meaning, "evidence candidate.meaning"),
    promotionReason: nonEmpty(item.promotionReason, "evidence candidate.promotionReason"),
    validationRequirements: uniqueTextList(item.validationRequirements, "evidence candidate.validationRequirements"),
    state,
    sensitivity: enumValue(item.sensitivity, SENSITIVITIES, "evidence candidate.sensitivity"),
    proposedBy: identifier(item.proposedBy, "evidence candidate.proposedBy"),
    ...(reviewedBy ? { reviewedBy } : {}),
    ...(reviewReason ? { reviewReason } : {}),
    ...(promotedEvidenceId ? { promotedEvidenceId } : {}),
    createdAt: timestamp(item.createdAt, "evidence candidate.createdAt"),
    ...(reviewedAt ? { reviewedAt } : {}),
  };
}

export function parseEvidenceCandidatePage(payload: unknown): OperationalTruthPage<EvidenceCandidateV24> {
  return page(payload, "evidence candidate page", parseEvidenceCandidate);
}

export function parseEvidenceCandidateDetail(payload: unknown): EvidenceCandidateDetailV24 {
  const root = object(payload, "evidence candidate detail");
  schema(root);
  return { schemaVersion: "2.4", candidate: parseEvidenceCandidate(root.candidate) };
}

export function parseEvidenceCandidateMutation(payload: unknown): EvidenceCandidateMutationV24 {
  return parseEvidenceCandidateDetail(payload);
}

export function parseVerifiedEvidence(value: unknown): VerifiedEvidenceV24 {
  const item = object(value, "verified evidence");
  if (item.verificationState !== "verified") throw new Error("verified evidence state is invalid");
  return {
    id: identifier(item.id, "verified evidence.id"),
    missionId: identifier(item.missionId, "verified evidence.missionId"),
    ...optionalIds(item, ["runId", "stepId", "artifactId"]),
    source: nonEmpty(item.source, "verified evidence.source"),
    acquiredAt: timestamp(item.acquiredAt, "verified evidence.acquiredAt"),
    target: nonEmpty(item.target, "verified evidence.target"),
    evidenceType: nonEmpty(item.evidenceType, "verified evidence.evidenceType"),
    contentHash: contentHash(item.contentHash, "verified evidence.contentHash"),
    provenance: jsonValue(item.provenance, "verified evidence.provenance"),
    confidence: confidence(item.confidence, "verified evidence.confidence"),
    sensitivity: enumValue(item.sensitivity, SENSITIVITIES, "verified evidence.sensitivity"),
    verificationState: "verified",
    summary: nonEmpty(item.summary, "verified evidence.summary"),
    createdBy: identifier(item.createdBy, "verified evidence.createdBy"),
    createdAt: timestamp(item.createdAt, "verified evidence.createdAt"),
  };
}

function parseCustodyEvent(value: unknown): EvidenceCustodyEventV24 {
  const item = object(value, "evidence custody event");
  return {
    id: identifier(item.id, "evidence custody event.id"),
    evidenceId: identifier(item.evidenceId, "evidence custody event.evidenceId"),
    eventType: nonEmpty(item.eventType, "evidence custody event.eventType"),
    actor: identifier(item.actor, "evidence custody event.actor"),
    details: jsonValue(item.details, "evidence custody event.details"),
    occurredAt: timestamp(item.occurredAt, "evidence custody event.occurredAt"),
  };
}

export function parseVerifiedEvidencePage(payload: unknown): OperationalTruthPage<VerifiedEvidenceV24> {
  return page(payload, "verified evidence page", parseVerifiedEvidence);
}

export function parseVerifiedEvidenceMutation(payload: unknown): VerifiedEvidenceMutationV24 {
  const root = object(payload, "verified evidence mutation");
  schema(root);
  return { schemaVersion: "2.4", evidence: parseVerifiedEvidence(root.evidence) };
}

export function parseVerifiedEvidenceDetail(payload: unknown): VerifiedEvidenceDetailV24 {
  const root = object(payload, "verified evidence detail");
  schema(root);
  const evidence = parseVerifiedEvidence(root.evidence);
  const chainOfCustody = array(root.chainOfCustody, "verified evidence chain of custody").map(parseCustodyEvent);
  if (chainOfCustody.some((event) => event.evidenceId !== evidence.id)) {
    throw new Error("verified evidence chain of custody references another evidence record");
  }
  return { schemaVersion: "2.4", evidence, chainOfCustody };
}

export function parseFailureDiagnosis(value: unknown): FailureDiagnosisV24 {
  const item = object(value, "failure diagnosis");
  const state = enumValue(item.state, FAILURE_STATES, "failure diagnosis.state");
  const resolvedAt = optionalTimestamp(item.resolvedAt, "failure diagnosis.resolvedAt");
  if ((state === "resolved") !== Boolean(resolvedAt)) {
    throw new Error("failure diagnosis resolution state and timestamp are inconsistent");
  }
  const preservedReferences = array(item.preservedReferences, "failure diagnosis.preservedReferences").map((value, index) => {
    const reference = object(value, `failure diagnosis.preservedReferences[${index}]`);
    return {
      kind: enumValue(reference.kind, FAILURE_REFERENCE_KINDS, `failure diagnosis.preservedReferences[${index}].kind`),
      id: identifier(reference.id, `failure diagnosis.preservedReferences[${index}].id`),
      meaning: nonEmpty(reference.meaning, `failure diagnosis.preservedReferences[${index}].meaning`),
    };
  });
  const operatorActions = array(item.operatorActions, "failure diagnosis.operatorActions").map((value, index) => {
    const action = object(value, `failure diagnosis.operatorActions[${index}]`);
    return {
      kind: enumValue(action.kind, FAILURE_ACTION_KINDS, `failure diagnosis.operatorActions[${index}].kind`),
      label: nonEmpty(action.label, `failure diagnosis.operatorActions[${index}].label`),
      consequence: nonEmpty(action.consequence, `failure diagnosis.operatorActions[${index}].consequence`),
      requiresConfirmation: boolean(action.requiresConfirmation, `failure diagnosis.operatorActions[${index}].requiresConfirmation`),
    };
  });
  if (operatorActions.length === 0) throw new Error("failure diagnosis.operatorActions cannot be empty");
  return {
    id: identifier(item.id, "failure diagnosis.id"),
    missionId: identifier(item.missionId, "failure diagnosis.missionId"),
    ...optionalIds(item, [
      "runId", "stepId", "assignmentId", "actionId", "attackAttemptId", "lastSuccessEventId", "rawErrorLogId",
    ]),
    subjectType: enumValue(item.subjectType, FAILURE_SUBJECTS, "failure diagnosis.subjectType"),
    subjectId: identifier(item.subjectId, "failure diagnosis.subjectId"),
    humanReason: nonEmpty(item.humanReason, "failure diagnosis.humanReason"),
    category: enumValue(item.category, FAILURE_CATEGORIES, "failure diagnosis.category"),
    code: identifier(item.code, "failure diagnosis.code"),
    originatingComponent: identifier(item.originatingComponent, "failure diagnosis.originatingComponent"),
    ...(optionalText(item.failedComponentRef, "failure diagnosis.failedComponentRef") === undefined
      ? {} : { failedComponentRef: optionalText(item.failedComponentRef, "failure diagnosis.failedComponentRef") }),
    ...(optionalText(item.targetSummary, "failure diagnosis.targetSummary") === undefined
      ? {} : { targetSummary: optionalText(item.targetSummary, "failure diagnosis.targetSummary") }),
    ...(optionalText(item.policyOrDependency, "failure diagnosis.policyOrDependency") === undefined
      ? {} : { policyOrDependency: optionalText(item.policyOrDependency, "failure diagnosis.policyOrDependency") }),
    retryHistory: jsonValue(item.retryHistory, "failure diagnosis.retryHistory"),
    progressBeforeFailure: jsonValue(item.progressBeforeFailure, "failure diagnosis.progressBeforeFailure"),
    preservedReferences,
    retryable: boolean(item.retryable, "failure diagnosis.retryable"),
    automaticRecovery: jsonValue(item.automaticRecovery, "failure diagnosis.automaticRecovery"),
    remediation: nonEmpty(item.remediation, "failure diagnosis.remediation"),
    operatorActions,
    objectiveImpact: nonEmpty(item.objectiveImpact, "failure diagnosis.objectiveImpact"),
    state,
    createdAt: timestamp(item.createdAt, "failure diagnosis.createdAt"),
    ...(resolvedAt ? { resolvedAt } : {}),
  };
}

export function parseFailureDiagnosisList(payload: unknown): FailureDiagnosisListV24 {
  const root = object(payload, "failure diagnosis list");
  schema(root);
  return {
    schemaVersion: "2.4",
    items: array(root.items, "failure diagnosis list.items").map(parseFailureDiagnosis),
  };
}

export function parseFailureDiagnosisDetail(payload: unknown): FailureDiagnosisDetailV24 {
  const root = object(payload, "failure diagnosis detail");
  schema(root);
  return { schemaVersion: "2.4", diagnosis: parseFailureDiagnosis(root.diagnosis) };
}

export function parseFailureDiagnosisMutation(payload: unknown): FailureDiagnosisMutationV24 {
  return parseFailureDiagnosisDetail(payload);
}

import {
  JOURNEYS,
  MEMORY_AUTHOR_TYPES,
  MEMORY_EDGE_TYPES,
  MEMORY_LIFECYCLE_STATES,
  MEMORY_NODE_TYPES,
  MEMORY_SENSITIVITIES,
  MEMORY_SCOPE_KINDS,
  type CreateMemoryEdgeInput,
  type CreateMemoryNodeInput,
  type Journey,
  type MemoryAuthorType,
  type MemoryEdgeType,
  type MemoryLifecycle,
  type MemoryNodeType,
  type MemoryProvenance,
  type MemoryScope,
  type MemorySensitivity,
} from "./types";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const NON_EMPTY_MAX = 20_000;

function oneOf<T extends string>(value: unknown, values: readonly T[], label: string): T {
  if (typeof value !== "string" || !(values as readonly string[]).includes(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value as T;
}

export function assertIdentifier(value: string, label: string): void {
  if (!IDENTIFIER.test(value)) throw new TypeError(`${label} is invalid`);
}

export function assertNonEmpty(value: string, label: string, maximum = NON_EMPTY_MAX): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new TypeError(`${label} must contain 1-${maximum} characters`);
  }
}

export function assertOptionalTimestamp(value: string | undefined | null, label: string): void {
  if (value === undefined || value === null) return;
  if (!Number.isFinite(Date.parse(value))) throw new TypeError(`${label} must be an ISO timestamp`);
}

export function validateNodeType(value: unknown): MemoryNodeType {
  return oneOf(value, MEMORY_NODE_TYPES, "memory node type");
}

export function validateEdgeType(value: unknown): MemoryEdgeType {
  return oneOf(value, MEMORY_EDGE_TYPES, "memory edge type");
}

export function validateLifecycle(value: unknown): MemoryLifecycle {
  return oneOf(value, MEMORY_LIFECYCLE_STATES, "memory lifecycle state");
}

export function validateSensitivity(value: unknown): MemorySensitivity {
  return oneOf(value, MEMORY_SENSITIVITIES, "memory sensitivity");
}

export function validateAuthorType(value: unknown): MemoryAuthorType {
  return oneOf(value, MEMORY_AUTHOR_TYPES, "memory author type");
}

export function validateJourney(value: unknown): Journey {
  return oneOf(value, JOURNEYS, "journey");
}

export function validateConfidence(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new TypeError("memory confidence must be between 0 and 1");
  }
  return value;
}

export function validateScope(scope: MemoryScope): MemoryScope {
  oneOf(scope?.kind, MEMORY_SCOPE_KINDS, "memory scope");
  if (scope.engagementId) assertIdentifier(scope.engagementId, "engagement ID");
  if (scope.missionId) assertIdentifier(scope.missionId, "mission ID");
  if (scope.kind === "global" && (scope.engagementId || scope.missionId)) {
    throw new TypeError("global memory cannot carry engagement or mission identifiers");
  }
  if (scope.kind === "engagement" && (!scope.engagementId || scope.missionId)) {
    throw new TypeError("engagement memory requires only an engagement ID");
  }
  if (scope.kind === "mission" && !scope.missionId) {
    throw new TypeError("mission memory requires a mission ID");
  }
  return scope;
}

export function validateProvenance(provenance: MemoryProvenance): MemoryProvenance {
  const methods = ["operator_statement", "observation", "evidence", "derived", "imported"];
  if (!provenance || !methods.includes(provenance.method)) {
    throw new TypeError("memory provenance method is invalid");
  }
  assertNonEmpty(provenance.explanation, "memory provenance explanation", 2_000);
  if (!Array.isArray(provenance.sources) || provenance.sources.length === 0) {
    throw new TypeError("memory provenance requires at least one source");
  }
  for (const [index, source] of provenance.sources.entries()) {
    assertNonEmpty(source.sourceType, `provenance source ${index} type`, 128);
    assertNonEmpty(source.sourceId, `provenance source ${index} ID`, 512);
    assertOptionalTimestamp(source.acquiredAt, `provenance source ${index} timestamp`);
    if (source.sourceHash && !/^[a-f0-9]{64}$/i.test(source.sourceHash)) {
      throw new TypeError(`provenance source ${index} hash must be SHA-256`);
    }
    if (source.excerptRedacted && source.excerptRedacted.length > 4_000) {
      throw new TypeError(`provenance source ${index} excerpt is too long`);
    }
  }
  return provenance;
}

export function validateCreateNode(input: CreateMemoryNodeInput): void {
  if (input.id) assertIdentifier(input.id, "memory node ID");
  validateNodeType(input.nodeType);
  assertNonEmpty(input.title, "memory title", 500);
  assertNonEmpty(input.summary, "memory summary", 4_000);
  if ((input.body ?? "").length > 1_000_000) throw new TypeError("memory body is too large");
  validateScope(input.scope);
  validateSensitivity(input.sensitivity);
  validateConfidence(input.confidence);
  validateLifecycle(input.lifecycleStatus);
  if (input.lifecycleStatus === "forgotten") {
    throw new TypeError("forgotten is an erasure state and cannot be used for new memory");
  }
  validateAuthorType(input.authorType);
  validateProvenance(input.provenance);
  assertOptionalTimestamp(input.expiresAt, "memory expiry");
  if (input.nodeType === "preference" && input.authorType !== "operator") {
    if (input.lifecycleStatus !== "candidate" || input.confirmationState !== "pending") {
      throw new TypeError("non-operator preferences must remain pending candidates");
    }
  }
  if (input.lifecycleStatus === "confirmed" && input.confirmationState !== "confirmed") {
    throw new TypeError("confirmed memory requires confirmed consent state");
  }
}

export function validateCreateEdge(input: CreateMemoryEdgeInput): void {
  if (input.id) assertIdentifier(input.id, "memory edge ID");
  assertIdentifier(input.sourceNodeId, "source node ID");
  assertIdentifier(input.targetNodeId, "target node ID");
  if (input.sourceNodeId === input.targetNodeId) throw new TypeError("memory edges cannot self-link");
  validateEdgeType(input.edgeType);
  assertNonEmpty(input.title, "edge title", 500);
  assertNonEmpty(input.summary, "edge summary", 4_000);
  assertNonEmpty(input.explanation, "edge explanation", 4_000);
  validateScope(input.scope);
  validateSensitivity(input.sensitivity);
  validateConfidence(input.confidence);
  validateLifecycle(input.lifecycleStatus);
  validateAuthorType(input.authorType);
  validateProvenance(input.provenance);
  assertOptionalTimestamp(input.expiresAt, "edge expiry");
}

export function serializeScope(scope: MemoryScope): string {
  return scope.kind;
}

export function deserializeScope(
  scope: string,
  engagementId?: string | null,
  missionId?: string | null,
): MemoryScope {
  const kind = oneOf(scope, MEMORY_SCOPE_KINDS, "stored memory scope");
  return validateScope({
    kind,
    ...(engagementId ? { engagementId } : {}),
    ...(missionId ? { missionId } : {}),
  });
}

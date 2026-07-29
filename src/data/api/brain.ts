import {
  parseBrainSummary,
  parseAttackKnowledgeVaultPresetPreview,
  parseAttackKnowledgeVaultScopeAmendment,
  parseCandidateRejection,
  parseForgetMutation,
  parseMemoryCandidatePage,
  parseMemoryContextPack,
  parseMemoryContextPackPage,
  parseMemoryControlPolicy,
  parseMemoryGraph,
  parseMemoryNodeDetail,
  parseMemoryNodePage,
  parseMemoryOriginPage,
  parseMemorySourcePage,
  parseNodeMutation,
  parseOperationalHazardAggregateObservationResult,
  parseOperationalHazardResetTotals,
  parseOperatorPreferencePage,
  parseVaultConnectionMutation,
  parseVaultDisconnectMutation,
  parseVaultHealthCheck,
  parseVaultOperation,
  parseVaultRecovery,
  parseVaultSnapshot,
} from "../../domain/schemas/brain";
import type {
  BrainSummary,
  AttackKnowledgeVaultPresetPreview,
  AttackKnowledgeVaultScopeAmendment,
  MemoryCandidatePage,
  MemoryContextPack,
  MemoryContextPackPage,
  MemoryContextPackQuery,
  MemoryControlPolicy,
  MemoryGraph,
  MemoryGraphQuery,
  MemoryLifecycle,
  MemoryNode,
  MemoryNodeDetail,
  MemoryNodePage,
  MemoryOriginPage,
  MemorySourcePage,
  MemoryNodeQuery,
  MemoryScope,
  MemorySensitivity,
  OperationalHazardAggregateObservationResult,
  OperationalHazardResetTotals,
  OperatorPreferencePage,
  VaultConnection,
  VaultDisconnectMutation,
  VaultHealthCheckResult,
  VaultOperationResult,
  VaultRecoveryResult,
  VaultSnapshot,
} from "../../domain/types/brain";
import { apiRequest } from "./client";

const ROOT = "/api/v2/brain";

function queryString(values: object): string {
  const query = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && String(value).trim()) query.set(key, String(value));
  });
  const result = query.toString();
  return result ? `?${result}` : "";
}

export function createBrainMutationKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `brain-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function mutation<T>(
  path: string,
  body: unknown,
  parse: (payload: unknown) => T,
  method = "POST",
  idempotencyKey = createBrainMutationKey(),
): Promise<T> {
  return apiRequest(`${ROOT}${path}`, {
    method,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(body),
    parse,
  });
}

export function fetchBrainSummary(signal: AbortSignal): Promise<BrainSummary> {
  return apiRequest(`${ROOT}/summary`, { signal, parse: parseBrainSummary });
}

export function fetchMemoryControl(signal: AbortSignal): Promise<MemoryControlPolicy> {
  return apiRequest(`${ROOT}/control`, { signal, parse: parseMemoryControlPolicy });
}

export function updateMemoryControl(
  expectedVersion: number,
  policy: Omit<MemoryControlPolicy, "version" | "updatedBy" | "updatedAt">,
): Promise<MemoryControlPolicy> {
  return mutation("/control", { expectedVersion, policy }, parseMemoryControlPolicy, "PUT");
}

export function fetchMemoryNodes(filters: MemoryNodeQuery, signal: AbortSignal): Promise<MemoryNodePage> {
  return apiRequest(`${ROOT}/nodes${queryString(filters)}`, { signal, parse: parseMemoryNodePage });
}

export function fetchMemoryGraph(filters: MemoryGraphQuery, signal: AbortSignal): Promise<MemoryGraph> {
  return apiRequest(`${ROOT}/graph${queryString(filters)}`, { signal, parse: parseMemoryGraph });
}

export function fetchMemoryNode(nodeId: string, signal: AbortSignal): Promise<MemoryNodeDetail> {
  return apiRequest(`${ROOT}/nodes/${encodeURIComponent(nodeId)}`, { signal, parse: parseMemoryNodeDetail });
}

export function fetchMemorySources(
  nodeId: string,
  signal: AbortSignal,
  options: { readonly limit?: number; readonly cursor?: string } = {},
): Promise<MemorySourcePage> {
  return apiRequest(
    `${ROOT}/nodes/${encodeURIComponent(nodeId)}/sources${queryString(options)}`,
    { signal, parse: parseMemorySourcePage },
  );
}

export function fetchMemorySourceOrigins(
  nodeId: string,
  sourceRecordId: string,
  signal: AbortSignal,
  options: { readonly limit?: number; readonly cursor?: string } = {},
): Promise<MemoryOriginPage> {
  return apiRequest(
    `${ROOT}/nodes/${encodeURIComponent(nodeId)}/sources/${encodeURIComponent(sourceRecordId)}/origins${queryString(options)}`,
    { signal, parse: parseMemoryOriginPage },
  );
}

export function fetchOperatorPreferences(signal: AbortSignal): Promise<OperatorPreferencePage> {
  return apiRequest(`${ROOT}/preferences`, { signal, parse: parseOperatorPreferencePage });
}

export function fetchOperationalHazardResetTotals(
  missionId: string,
  runId: string,
  signal: AbortSignal,
): Promise<OperationalHazardResetTotals> {
  return apiRequest(
    `/api/v2/missions/${encodeURIComponent(missionId)}/runs/${encodeURIComponent(runId)}/operational-hazards/reset-totals`,
    { signal, parse: parseOperationalHazardResetTotals },
  );
}

export function reportOperationalHazardResetMinimum(
  input: { missionId: string; runId: string; reportedMinimum: number },
  idempotencyKey = createBrainMutationKey(),
): Promise<OperationalHazardAggregateObservationResult> {
  if (!Number.isSafeInteger(input.reportedMinimum) || input.reportedMinimum < 1) {
    throw new RangeError("Overall reset minimum must be a positive whole number");
  }
  return apiRequest(
    `/api/v2/missions/${encodeURIComponent(input.missionId)}/runs/${encodeURIComponent(input.runId)}/operational-hazards/reset-minimum-observations`,
    {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify({ reportedMinimum: input.reportedMinimum }),
      parse: parseOperationalHazardAggregateObservationResult,
    },
  );
}

export interface MemoryCandidateQuery {
  missionId?: string;
  runId?: string;
  status?: MemoryCandidatePage["items"][number]["status"];
  cursor?: string;
  limit?: number;
}

export function fetchMemoryCandidates(signal: AbortSignal): Promise<MemoryCandidatePage>;
export function fetchMemoryCandidates(filters: MemoryCandidateQuery, signal: AbortSignal): Promise<MemoryCandidatePage>;
export function fetchMemoryCandidates(
  filtersOrSignal: MemoryCandidateQuery | AbortSignal,
  maybeSignal?: AbortSignal,
): Promise<MemoryCandidatePage> {
  const signal = filtersOrSignal instanceof AbortSignal ? filtersOrSignal : maybeSignal;
  const filters = filtersOrSignal instanceof AbortSignal ? {} : filtersOrSignal;
  return apiRequest(`${ROOT}/candidates${queryString(filters)}`, { signal, parse: parseMemoryCandidatePage });
}

export function confirmMemoryCandidate(candidateId: string, edits?: {
  title?: string;
  summary?: string;
  body?: string;
  sensitivity?: MemorySensitivity;
  scope?: MemoryScope;
}): Promise<MemoryNode> {
  return mutation(`/candidates/${encodeURIComponent(candidateId)}/confirm`, { edits: edits ?? {} }, parseNodeMutation);
}

export function rejectMemoryCandidate(candidateId: string, reason: string, doNotRelearn: boolean): Promise<{ status: string; suppressionId?: string }> {
  return mutation(`/candidates/${encodeURIComponent(candidateId)}/reject`, { reason, doNotRelearn }, parseCandidateRejection);
}

export function correctMemoryNode(nodeId: string, expectedVersion: number, changes: {
  title?: string;
  summary?: string;
  body?: string;
  scope?: MemoryScope;
  sensitivity?: MemorySensitivity;
  lifecycleStatus?: Exclude<MemoryLifecycle, "forgotten">;
  expiresAt?: string | null;
  pinned?: boolean;
}, reason: string): Promise<MemoryNode> {
  return mutation(`/nodes/${encodeURIComponent(nodeId)}/correct`, { expectedVersion, ...changes, reason }, parseNodeMutation);
}

export function disputeMemoryNode(nodeId: string, expectedVersion: number, reason: string): Promise<MemoryNode> {
  return mutation(`/nodes/${encodeURIComponent(nodeId)}/dispute`, { expectedVersion, reason }, parseNodeMutation);
}

export function pinMemoryNode(nodeId: string, expectedVersion: number, pinned: boolean): Promise<MemoryNode> {
  return mutation(`/nodes/${encodeURIComponent(nodeId)}/pin`, { expectedVersion, pinned }, parseNodeMutation);
}

export function expireMemoryNode(nodeId: string, expectedVersion: number, expiresAt: string, reason: string): Promise<MemoryNode> {
  return mutation(`/nodes/${encodeURIComponent(nodeId)}/expire`, { expectedVersion, expiresAt, reason }, parseNodeMutation);
}

export function forgetMemoryNode(nodeId: string, expectedVersion: number, reason: string): Promise<{ suppressionId: string }> {
  return mutation(`/nodes/${encodeURIComponent(nodeId)}/forget`, { expectedVersion, reason }, parseForgetMutation);
}

export function fetchContextPack(packId: string, signal: AbortSignal): Promise<MemoryContextPack> {
  return apiRequest(`${ROOT}/context-packs/${encodeURIComponent(packId)}`, { signal, parse: parseMemoryContextPack });
}

export function fetchContextPacks(filters: MemoryContextPackQuery, signal: AbortSignal): Promise<MemoryContextPackPage> {
  return apiRequest(`${ROOT}/context-packs${queryString(filters)}`, { signal, parse: parseMemoryContextPackPage });
}

export function fetchVaultSnapshot(signal: AbortSignal): Promise<VaultSnapshot> {
  return apiRequest(`${ROOT}/vault`, { signal, parse: parseVaultSnapshot });
}

export function fetchAttackKnowledgeVaultPreset(
  includeConfirmed: boolean,
  signal: AbortSignal,
  includeOperatorProfile = false,
): Promise<AttackKnowledgeVaultPresetPreview> {
  if (includeOperatorProfile && !includeConfirmed) {
    throw new TypeError("Operator Profile Vault preview requires confirmed knowledge scope");
  }
  return apiRequest(
    `${ROOT}/vault/attack-knowledge-preset?includeConfirmed=${includeConfirmed ? "true" : "false"}&includeOperatorProfile=${includeOperatorProfile ? "true" : "false"}`,
    { signal, parse: parseAttackKnowledgeVaultPresetPreview },
  );
}

export function activateAttackKnowledgeVaultPreset(
  input: {
    expectedPolicyHash: string;
    includeConfirmed: boolean;
    permissionGranted: true;
    activationAcknowledged: true;
  },
): Promise<VaultConnection> {
  return mutation(
    "/vault/attack-knowledge-preset/activate",
    input,
    parseVaultConnectionMutation,
  );
}

export function amendAttackKnowledgeVaultPreset(
  input: {
    connectionId: string;
    expectedUpdatedAt: string;
    expectedCurrentPolicyHash: string;
    expectedTargetPolicyHash: string;
    includeConfirmed: true;
    permissionGranted: true;
    reason: string;
  } & (
    | { amendmentAcknowledged: true; includeOperatorProfile?: false }
    | { includeOperatorProfile: true; operatorProfileAcknowledged: true }
  ),
): Promise<AttackKnowledgeVaultScopeAmendment> {
  return mutation(
    "/vault/attack-knowledge-preset/amend",
    input,
    parseAttackKnowledgeVaultScopeAmendment,
  );
}

export function connectVault(input: {
  vaultPath: string;
  displayName: string;
  permissionGranted: true;
  syncScope?: Record<string, unknown>;
}): Promise<VaultConnection> {
  return mutation("/vault/connect", input, parseVaultConnectionMutation);
}

export function disconnectVault(
  input: {
    connectionId: string;
    expectedUpdatedAt: string;
    reason: string;
    disconnectAcknowledged: true;
    allowProjectionDegraded: boolean;
  },
  idempotencyKey = createBrainMutationKey(),
): Promise<VaultDisconnectMutation> {
  return mutation(
    `/vault/${encodeURIComponent(input.connectionId)}/disconnect`,
    {
      expectedUpdatedAt: input.expectedUpdatedAt,
      reason: input.reason,
      disconnectAcknowledged: input.disconnectAcknowledged,
      allowProjectionDegraded: input.allowProjectionDegraded,
      controlPlane: "ti_scale",
    },
    parseVaultDisconnectMutation,
    "POST",
    idempotencyKey,
  );
}

export function checkVaultHealth(input:
  | { vaultPath: string; permissionGranted: true }
  | { connectionId: string }
): Promise<VaultHealthCheckResult> {
  return mutation("/vault/health-check", input, parseVaultHealthCheck);
}

export function exportVault(connectionId: string, nodeId?: string): Promise<VaultOperationResult> {
  return mutation("/vault/export", { connectionId, ...(nodeId ? { nodeId } : {}) }, parseVaultOperation);
}

export function importVault(connectionId: string): Promise<VaultOperationResult> {
  return mutation("/vault/import", { connectionId }, parseVaultOperation);
}

export function syncVault(connectionId: string): Promise<VaultOperationResult> {
  return mutation("/vault/sync", { connectionId }, parseVaultOperation);
}

export function repairVault(
  connectionId: string,
  expectedUpdatedAt: string,
  idempotencyKey = createBrainMutationKey(),
): Promise<VaultRecoveryResult> {
  return mutation("/vault/repair", {
    connectionId,
    expectedUpdatedAt,
    controlPlane: "ti_scale",
  }, parseVaultRecovery, "POST", idempotencyKey);
}

export function reindexVault(
  connectionId: string,
  expectedUpdatedAt: string,
  idempotencyKey = createBrainMutationKey(),
): Promise<VaultRecoveryResult> {
  return mutation("/vault/reindex", {
    connectionId,
    expectedUpdatedAt,
    controlPlane: "ti_scale",
  }, parseVaultRecovery, "POST", idempotencyKey);
}

export function resolveVaultConflict(conflictId: string, resolution: "database" | "vault"): Promise<VaultOperationResult> {
  return mutation(`/vault/conflicts/${encodeURIComponent(conflictId)}/resolve`, { resolution }, parseVaultOperation);
}

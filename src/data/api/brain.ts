import {
  parseBrainSummary,
  parseCandidateRejection,
  parseForgetMutation,
  parseMemoryCandidatePage,
  parseMemoryContextPack,
  parseMemoryContextPackPage,
  parseMemoryControlPolicy,
  parseMemoryGraph,
  parseMemoryNodeDetail,
  parseMemoryNodePage,
  parseNodeMutation,
  parseVaultConnectionMutation,
  parseVaultHealthCheck,
  parseVaultOperation,
  parseVaultRecovery,
  parseVaultSnapshot,
} from "../../domain/schemas/brain";
import type {
  BrainSummary,
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
  MemoryNodeQuery,
  MemoryScope,
  MemorySensitivity,
  VaultConnection,
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

export function connectVault(input: {
  vaultPath: string;
  displayName: string;
  permissionGranted: true;
  syncScope?: Record<string, unknown>;
}): Promise<VaultConnection> {
  return mutation("/vault/connect", input, parseVaultConnectionMutation);
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

export function portableExportVault(connectionId: string): Promise<VaultOperationResult> {
  return mutation("/vault/portable-export", { connectionId }, parseVaultOperation);
}

export function resolveVaultConflict(conflictId: string, resolution: "database" | "vault"): Promise<VaultOperationResult> {
  return mutation(`/vault/conflicts/${encodeURIComponent(conflictId)}/resolve`, { resolution }, parseVaultOperation);
}

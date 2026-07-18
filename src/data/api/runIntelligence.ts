import {
  parseAssetOsiStackDetail,
  parseAttackAttemptDetail,
  parseAttackAttemptList,
  parseReconDigitalTwinDetail,
  parseRunMetricsSnapshotDetail,
  parseRunMetricsSnapshotList,
  parseTopologyNodeDetail,
} from "../../domain/schemas/runIntelligence";
import type {
  AssetOsiStackDetail,
  AttackAttemptDetail,
  AttackAttemptList,
  ReconDigitalTwinDetail,
  RunMetricsSnapshotDetail,
  RunMetricsSnapshotList,
  TopologyNodeDetail,
} from "../../domain/types/runIntelligence";
import { apiRequest } from "./client";

function identifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${label} is required`);
  if (normalized.length > 200 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError(`${label} is invalid`);
  return encodeURIComponent(normalized);
}

function runRoot(runId: string): string {
  return `/api/v2/runs/${identifier(runId, "Run ID")}/intelligence`;
}

function missionRoot(missionId: string): string {
  return `/api/v2/missions/${identifier(missionId, "Mission ID")}/intelligence/topology`;
}

function scopedUrl(path: string, runId?: string): string {
  if (runId === undefined) return path;
  return `${path}?${new URLSearchParams({ runId: runId.trim() }).toString()}`;
}

export const runIntelligenceApi = {
  listMetricSnapshots(runId: string, limit = 50, signal?: AbortSignal): Promise<RunMetricsSnapshotList> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new RangeError("Metrics snapshot limit must be from 1 through 100");
    const path = `${runRoot(runId)}/metrics/snapshots?${new URLSearchParams({ limit: String(limit) }).toString()}`;
    return apiRequest(path, { method: "GET", signal, parse: parseRunMetricsSnapshotList });
  },

  getMetricSnapshot(runId: string, snapshotId: string, signal?: AbortSignal): Promise<RunMetricsSnapshotDetail> {
    return apiRequest(`${runRoot(runId)}/metrics/snapshots/${identifier(snapshotId, "Snapshot ID")}`, {
      method: "GET", signal, parse: parseRunMetricsSnapshotDetail,
    });
  },

  listAttackAttempts(runId: string, signal?: AbortSignal): Promise<AttackAttemptList> {
    return apiRequest(`${runRoot(runId)}/attack-attempts`, { method: "GET", signal, parse: parseAttackAttemptList });
  },

  getAttackAttempt(runId: string, attemptId: string, signal?: AbortSignal): Promise<AttackAttemptDetail> {
    return apiRequest(`${runRoot(runId)}/attack-attempts/${identifier(attemptId, "Attack attempt ID")}`, {
      method: "GET", signal, parse: parseAttackAttemptDetail,
    });
  },

  getMissionTopology(missionId: string, runId?: string, signal?: AbortSignal): Promise<ReconDigitalTwinDetail> {
    const path = scopedUrl(missionRoot(missionId), runId === undefined ? undefined : decodeURIComponent(identifier(runId, "Run ID")));
    return apiRequest(path, { method: "GET", signal, parse: parseReconDigitalTwinDetail });
  },

  getTopologyNode(missionId: string, nodeId: string, runId?: string, signal?: AbortSignal): Promise<TopologyNodeDetail> {
    const path = `${missionRoot(missionId)}/nodes/${identifier(nodeId, "Topology node ID")}`;
    return apiRequest(scopedUrl(path, runId === undefined ? undefined : decodeURIComponent(identifier(runId, "Run ID"))), {
      method: "GET", signal, parse: parseTopologyNodeDetail,
    });
  },

  getAssetOsiStack(missionId: string, assetNodeId: string, runId?: string, signal?: AbortSignal): Promise<AssetOsiStackDetail> {
    const path = `${missionRoot(missionId)}/assets/${identifier(assetNodeId, "Asset node ID")}/osi`;
    return apiRequest(scopedUrl(path, runId === undefined ? undefined : decodeURIComponent(identifier(runId, "Run ID"))), {
      method: "GET", signal, parse: parseAssetOsiStackDetail,
    });
  },
};

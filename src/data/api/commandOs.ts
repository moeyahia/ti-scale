import {
  parseAutonomousBranchContext,
  parseAutonomousBranchPreflight,
  parseAutonomousBranchResult,
  parseAutonomousMissionPreflight,
  parseCreatedMission,
  parseMissionBulkArchive,
  parseMissionBulkExport,
  parseMissionPage,
  parseOverview,
  parseSavedMissionViewCollection,
} from "../../domain/schemas/commandOs";
import type {
  AutonomousBranchContext,
  AutonomousBranchMode,
  AutonomousBranchPreflight,
  AutonomousBranchResult,
  AutonomousMissionPreflight,
  AutonomousMissionRequest,
  CreatedMission,
  Journey,
  MissionCreateRequest,
  MissionBulkArchiveResult,
  MissionBulkExportResult,
  MissionPage,
  MissionPortfolioFilterState,
  OverviewSnapshot,
  SavedMissionViewCollection,
} from "../../domain/types/commandOs";
import { parseIntakeRegistrySnapshot, parseResolvedMissionIntake } from "../../domain/schemas/intake";
import type { IntakeRegistrySnapshot, MissionIntakeRequest, MissionTemplateId, ResolvedMissionIntake } from "../../domain/types/intake";
import { apiRequest } from "./client";
import { queryPath } from "./operations";

export function fetchOverview(signal?: AbortSignal): Promise<OverviewSnapshot> {
  return apiRequest("/api/v2/overview", {
    method: "GET",
    signal,
    parse: parseOverview,
  });
}

export function fetchMissionIntakeRegistry(
  journey: Journey,
  templateId: MissionTemplateId,
  signal?: AbortSignal,
): Promise<IntakeRegistrySnapshot> {
  return apiRequest(queryPath("/api/v2/registries/intake", { journey, templateId }), {
    method: "GET",
    signal,
    parse: parseIntakeRegistrySnapshot,
  });
}

export function resolveMissionIntake(
  request: MissionIntakeRequest,
  signal?: AbortSignal,
): Promise<ResolvedMissionIntake> {
  return apiRequest("/api/v2/registries/intake/resolve", {
    method: "POST",
    signal,
    body: JSON.stringify(request),
    parse: parseResolvedMissionIntake,
  });
}

export function fetchMissions(
  query: {
    cursor?: string; limit?: number; journey?: Journey; status?: string; query?: string;
    engagement?: string; target?: string; agent?: string; provider?: string;
    updatedFrom?: string; updatedTo?: string; risk?: string; evidence?: "present" | "none";
    findingSeverity?: string; decisionState?: string; recoveryState?: "recovering" | "blocked" | "none";
  } = {},
  signal?: AbortSignal,
): Promise<MissionPage> {
  return apiRequest(queryPath("/api/v2/missions", query), {
    method: "GET",
    signal,
    parse: parseMissionPage,
  });
}

export function fetchSavedMissionViews(signal?: AbortSignal): Promise<SavedMissionViewCollection> {
  return apiRequest("/api/v2/missions/saved-views", {
    method: "GET",
    signal,
    parse: parseSavedMissionViewCollection,
  });
}

export function saveMissionView(
  request: { expectedVersion: number; name: string; state: MissionPortfolioFilterState },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<SavedMissionViewCollection> {
  return apiRequest("/api/v2/missions/saved-views", {
    method: "POST",
    signal,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(request),
    parse: parseSavedMissionViewCollection,
  });
}

export function deleteMissionView(
  viewId: string,
  expectedVersion: number,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<SavedMissionViewCollection> {
  return apiRequest(`/api/v2/missions/saved-views/${encodeURIComponent(viewId)}`, {
    method: "DELETE",
    signal,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({ expectedVersion }),
    parse: parseSavedMissionViewCollection,
  });
}

export function archiveMissions(
  missionIds: readonly string[],
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<MissionBulkArchiveResult> {
  return apiRequest("/api/v2/missions/bulk/archive", {
    method: "POST",
    signal,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({ missionIds, confirm: true }),
    parse: parseMissionBulkArchive,
  });
}

export function exportMissionMetadata(
  missionIds: readonly string[],
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<MissionBulkExportResult> {
  return apiRequest("/api/v2/missions/bulk/export", {
    method: "POST",
    signal,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({ missionIds, confirm: true }),
    parse: parseMissionBulkExport,
  });
}

export function createMission(
  request: MissionCreateRequest,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CreatedMission> {
  return apiRequest("/api/v2/missions", {
    method: "POST",
    signal,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(request),
    parse: parseCreatedMission,
  });
}

export function preflightAutonomousMission(
  request: AutonomousMissionRequest,
  signal?: AbortSignal,
): Promise<AutonomousMissionPreflight> {
  return apiRequest("/api/v2/missions/autonomous/preflight", {
    method: "POST",
    signal,
    body: JSON.stringify(request),
    parse: parseAutonomousMissionPreflight,
  });
}

export function fetchAutonomousBranchContext(
  missionId: string,
  sourceRunId: string,
  signal?: AbortSignal,
): Promise<AutonomousBranchContext> {
  return apiRequest(queryPath(
    `/api/v2/missions/${encodeURIComponent(missionId)}/autonomous-branches/context`,
    { sourceRunId },
  ), {
    method: "GET",
    signal,
    parse: parseAutonomousBranchContext,
  });
}

export interface AutonomousBranchPreflightRequest {
  sourceRunId: string;
  sourceRunVersion: number;
  mode: AutonomousBranchMode;
  reason: string;
  request?: AutonomousMissionRequest;
}

export function preflightAutonomousBranch(
  missionId: string,
  request: AutonomousBranchPreflightRequest,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<AutonomousBranchPreflight> {
  return apiRequest(`/api/v2/missions/${encodeURIComponent(missionId)}/autonomous-branches/preflight`, {
    method: "POST",
    signal,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(request),
    parse: parseAutonomousBranchPreflight,
  });
}

export interface CreateAutonomousBranchRequest {
  sourceRunId: string;
  sourceRunVersion: number;
  mode: AutonomousBranchMode;
  reason: string;
  draftContractId?: string;
  review: { version: number; hash: string };
}

export function createAutonomousBranch(
  missionId: string,
  request: CreateAutonomousBranchRequest,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<AutonomousBranchResult> {
  return apiRequest(`/api/v2/missions/${encodeURIComponent(missionId)}/autonomous-branches`, {
    method: "POST",
    signal,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(request),
    parse: parseAutonomousBranchResult,
  });
}

import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { canonicalJson, hashCanonical, sha256 } from "./canonical";
import { MissionApiError } from "./errors";
import type {
  Journey,
  MissionBulkArchiveResult,
  MissionBulkExportResult,
  MissionBulkItemOutcome,
  MissionExportRecord,
  MissionPortfolioFilterState,
  SavedMissionView,
  SavedMissionViewCollection,
} from "./types";

const MAX_SAVED_VIEWS = 12;
const MAX_BULK_MISSIONS = 50;
const TITLE_PREVIEW_LIMIT = 120;
const TERMINAL_RUN_STATES = new Set(["completed", "failed", "cancelled"]);
const TERMINAL_MISSION_STATES = new Set(["completed", "failed", "cancelled"]);

interface SettingRow {
  readonly value_json: string;
  readonly version: number;
}

interface StoredIdempotency<T> {
  readonly requestHash: string;
  readonly response: T;
}

interface ArchiveMissionRow {
  readonly id: string;
  readonly journey: Journey;
  readonly status: string;
  readonly latest_run_id: string | null;
  readonly latest_run_status: string | null;
}

export interface MissionArchiveAuthorityScope {
  readonly missionId: string;
  readonly runId: string;
}

export interface MissionArchiveMutationAuthority extends MissionArchiveAuthorityScope {
  /** Rechecked inside the same IMMEDIATE transaction as replay or archive. */
  readonly assertCurrent: () => void;
}

interface ExportMissionRow {
  readonly id: string;
  readonly name: string;
  readonly journey: Journey;
  readonly status: string;
  readonly authorization_status: string;
  readonly engagement_id: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly run_id: string | null;
  readonly run_status: string | null;
  readonly progress: number | null;
  readonly phase: string | null;
  readonly current_owner_id: string | null;
  readonly started_at: string | null;
  readonly ended_at: string | null;
}

function id(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

function actorKey(actorId: string): string {
  return sha256(actorId.normalize("NFKC"));
}

function savedViewsKey(actorId: string): string {
  return `mission.portfolio.saved-views.v1.${actorKey(actorId)}`;
}

function idempotencyKey(actorId: string, operation: string, key: string): string {
  return `idempotency.mission-portfolio.${operation}.${actorKey(actorId)}.${sha256(key)}`;
}

function parseCollection(value: string, version: number): SavedMissionViewCollection {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid saved views");
    const items = (parsed as { items?: unknown }).items;
    if (!Array.isArray(items)) throw new Error("invalid saved views");
    return {
      schemaVersion: "2.4",
      version,
      items: items as SavedMissionView[],
    };
  } catch {
    throw new Error("Saved mission views are corrupt");
  }
}

function conflict(code: string, humanMessage: string, remediation: string): MissionApiError {
  return new MissionApiError(409, code, humanMessage, {
    humanMessage,
    category: "conflict",
    remediation,
  });
}

function stableViewId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value);
}

function validateMissionSelection(missionIds: readonly string[]): void {
  if (missionIds.length < 1 || missionIds.length > MAX_BULK_MISSIONS) {
    throw new MissionApiError(400, "invalid_mission_selection", "Mission selection is invalid", {
      humanMessage: `Select between 1 and ${MAX_BULK_MISSIONS} missions.`,
      category: "invalid_input",
    });
  }
  if (new Set(missionIds).size !== missionIds.length || missionIds.some(
    (missionId) => !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(missionId),
  )) {
    throw new MissionApiError(400, "invalid_mission_selection", "Mission selection is invalid", {
      humanMessage: "Mission IDs must be valid and may appear only once.",
      category: "invalid_input",
    });
  }
}

function truncate(value: string, maximum: number): { value: string; truncated: boolean } {
  const characters = [...value];
  return characters.length <= maximum
    ? { value, truncated: false }
    : { value: characters.slice(0, maximum).join(""), truncated: true };
}

function findingCounts(database: SqliteDatabase, missionId: string): Record<string, number> {
  const result: Record<string, number> = {};
  const rows = database.prepare(`
    SELECT severity, COUNT(*) AS count FROM findings WHERE mission_id = ? GROUP BY severity
  `).all(missionId) as Array<{ severity: string; count: number }>;
  for (const row of rows) result[row.severity] = row.count;
  return result;
}

/**
 * Operator-scoped portfolio preferences and bounded administrative mutations.
 * This service stores no evidence bodies, objectives, target values, or secret
 * material in saved views or export idempotency records.
 */
export class MissionPortfolioService {
  private readonly events: EventRepository;

  constructor(private readonly database: SqliteDatabase) {
    this.events = new EventRepository(database);
  }

  /**
   * Resolve the exact latest-run fence for every selected mission before the
   * router asks the trusted runtime for lease proofs. Missing missions and
   * runless/import-only records cannot become mutation targets.
   */
  archiveAuthorityScopes(missionIds: readonly string[]): readonly MissionArchiveAuthorityScope[] {
    validateMissionSelection(missionIds);
    return missionIds.map((missionId) => {
      const row = this.database.prepare(`
        SELECT m.id AS mission_id, (
          SELECT r.id FROM runs r WHERE r.mission_id = m.id
          ORDER BY r.created_at DESC, r.id DESC LIMIT 1
        ) AS run_id
        FROM missions m WHERE m.id = ?
      `).get(missionId) as { mission_id: string; run_id: string | null } | undefined;
      if (!row) {
        throw new MissionApiError(404, "archive_mission_not_found", "Selected mission was not found", {
          humanMessage: "A selected mission is no longer available, so nothing was archived.",
          category: "not_found",
          details: { missionId },
          remediation: "Refresh the mission portfolio and confirm the exact current selection.",
        });
      }
      if (!row.run_id) {
        throw new MissionApiError(409, "archive_run_authority_unavailable", "Selected mission has no canonical run", {
          humanMessage: "A selected mission has no canonical V2 run that can authorize this mutation.",
          category: "policy_denied",
          details: { missionId },
          remediation: "Keep imported or runless mission history read-only, or create a V2-native run through the normal mission flow.",
        });
      }
      return { missionId: row.mission_id, runId: row.run_id };
    });
  }

  private readIdempotency<T>(actorId: string, operation: string, key: string, requestHash: string): T | undefined {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(idempotencyKey(actorId, operation, key)) as { value_json: string } | undefined;
    if (!row) return undefined;
    const stored = JSON.parse(row.value_json) as StoredIdempotency<T>;
    if (stored.requestHash !== requestHash) {
      throw conflict(
        "portfolio_idempotency_conflict",
        "This portfolio submission key was already used for a different request.",
        "Retry the materially different operation with a new Idempotency-Key.",
      );
    }
    return stored.response;
  }

  private storeIdempotency<T>(
    actorId: string,
    operation: string,
    key: string,
    requestHash: string,
    response: T,
    now: string,
  ): void {
    this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, ?, ?)
    `).run(
      idempotencyKey(actorId, operation, key),
      canonicalJson({ requestHash, response }),
      actorId,
      now,
    );
  }

  private appendAudit(input: {
    readonly actorId: string;
    readonly action: string;
    readonly resourceType: string;
    readonly resourceId?: string;
    readonly reason: string;
    readonly details: unknown;
    readonly occurredAt: string;
    readonly missionId?: string;
    readonly runId?: string;
    readonly journey?: Journey;
  }): void {
    const previous = this.database.prepare(
      "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
    ).get() as { record_hash: string } | undefined;
    const auditId = id("audit");
    const recordHash = hashCanonical({
      id: auditId,
      previousHash: previous?.record_hash ?? null,
      actor: input.actorId,
      action: input.action,
      resourceType: input.resourceType,
      resourceId: input.resourceId ?? null,
      missionId: input.missionId ?? null,
      runId: input.runId ?? null,
      journey: input.journey ?? null,
      details: input.details,
      occurredAt: input.occurredAt,
    });
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, 'operator', ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      auditId,
      input.missionId ?? null,
      input.runId ?? null,
      input.journey ?? null,
      input.actorId,
      input.action,
      input.resourceType,
      input.resourceId ?? null,
      input.reason,
      canonicalJson(input.details),
      previous?.record_hash ?? null,
      recordHash,
      input.occurredAt,
    );
  }

  listSavedViews(actorId: string): SavedMissionViewCollection {
    const row = this.database.prepare("SELECT value_json, version FROM settings WHERE key = ?")
      .get(savedViewsKey(actorId)) as SettingRow | undefined;
    return row ? parseCollection(row.value_json, row.version) : {
      schemaVersion: "2.4",
      version: 0,
      items: [],
    };
  }

  saveView(input: {
    readonly actorId: string;
    readonly idempotencyKey: string;
    readonly expectedVersion: number;
    readonly name: string;
    readonly state: MissionPortfolioFilterState;
  }): SavedMissionViewCollection {
    const requestHash = hashCanonical({
      expectedVersion: input.expectedVersion,
      name: input.name,
      state: input.state,
    });
    const replay = this.readIdempotency<SavedMissionViewCollection>(
      input.actorId, "save-view", input.idempotencyKey, requestHash,
    );
    if (replay) return replay;
    return inImmediateTransaction(this.database, () => {
      const concurrentReplay = this.readIdempotency<SavedMissionViewCollection>(
        input.actorId, "save-view", input.idempotencyKey, requestHash,
      );
      if (concurrentReplay) return concurrentReplay;
      const current = this.listSavedViews(input.actorId);
      if (current.version !== input.expectedVersion) {
        throw conflict(
          "saved_view_version_conflict",
          "Saved mission views changed in another session.",
          "Refresh saved views and retry your change.",
        );
      }
      const now = new Date().toISOString();
      const existing = current.items.find(
        (view) => view.name.toLocaleLowerCase("en-US") === input.name.toLocaleLowerCase("en-US"),
      );
      if (!existing && current.items.length >= MAX_SAVED_VIEWS) {
        throw conflict(
          "saved_view_limit_reached",
          `At most ${MAX_SAVED_VIEWS} mission views can be retained per operator.`,
          "Delete an unused view before saving another.",
        );
      }
      const saved: SavedMissionView = {
        id: existing?.id ?? id("mission_view"),
        name: input.name,
        state: input.state,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      const items = [saved, ...current.items.filter((view) => view.id !== saved.id)];
      const next: SavedMissionViewCollection = {
        schemaVersion: "2.4",
        version: current.version + 1,
        items,
      };
      this.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'private', 1, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
          value_json = excluded.value_json,
          version = settings.version + 1,
          updated_by = excluded.updated_by,
          updated_at = excluded.updated_at
      `).run(savedViewsKey(input.actorId), canonicalJson({ items }), input.actorId, now);
      this.appendAudit({
        actorId: input.actorId,
        action: "mission.saved_view.upserted",
        resourceType: "mission_saved_view",
        resourceId: saved.id,
        reason: "Operator synchronized a portfolio filter and layout view",
        details: { viewId: saved.id, collectionVersion: next.version, filterHash: hashCanonical(saved.state) },
        occurredAt: now,
      });
      this.storeIdempotency(input.actorId, "save-view", input.idempotencyKey, requestHash, next, now);
      return next;
    });
  }

  deleteView(input: {
    readonly actorId: string;
    readonly idempotencyKey: string;
    readonly expectedVersion: number;
    readonly viewId: string;
  }): SavedMissionViewCollection {
    if (!stableViewId(input.viewId)) {
      throw new MissionApiError(400, "invalid_saved_view_id", "Saved view ID is invalid", {
        humanMessage: "The saved mission view identifier is malformed.",
        category: "invalid_input",
      });
    }
    const requestHash = hashCanonical({ expectedVersion: input.expectedVersion, viewId: input.viewId });
    const replay = this.readIdempotency<SavedMissionViewCollection>(
      input.actorId, "delete-view", input.idempotencyKey, requestHash,
    );
    if (replay) return replay;
    return inImmediateTransaction(this.database, () => {
      const concurrentReplay = this.readIdempotency<SavedMissionViewCollection>(
        input.actorId, "delete-view", input.idempotencyKey, requestHash,
      );
      if (concurrentReplay) return concurrentReplay;
      const current = this.listSavedViews(input.actorId);
      if (current.version !== input.expectedVersion) {
        throw conflict("saved_view_version_conflict", "Saved mission views changed in another session.", "Refresh saved views and retry deletion.");
      }
      const removed = current.items.find((view) => view.id === input.viewId);
      const now = new Date().toISOString();
      const next = removed ? {
        schemaVersion: "2.4" as const,
        version: current.version + 1,
        items: current.items.filter((view) => view.id !== input.viewId),
      } : current;
      if (removed) {
        this.database.prepare(`
          UPDATE settings SET value_json = ?, version = version + 1, updated_by = ?, updated_at = ?
          WHERE key = ? AND version = ?
        `).run(
          canonicalJson({ items: next.items }), input.actorId, now,
          savedViewsKey(input.actorId), current.version,
        );
        this.appendAudit({
          actorId: input.actorId,
          action: "mission.saved_view.deleted",
          resourceType: "mission_saved_view",
          resourceId: input.viewId,
          reason: "Operator deleted a synchronized portfolio view",
          details: { viewId: input.viewId, collectionVersion: next.version },
          occurredAt: now,
        });
      }
      this.storeIdempotency(input.actorId, "delete-view", input.idempotencyKey, requestHash, next, now);
      return next;
    });
  }

  archive(input: {
    readonly actorId: string;
    readonly idempotencyKey: string;
    readonly missionIds: readonly string[];
    readonly mutationAuthorities: readonly MissionArchiveMutationAuthority[];
  }): MissionBulkArchiveResult {
    validateMissionSelection(input.missionIds);
    const selectionHash = hashCanonical(input.missionIds);
    const requestHash = hashCanonical({ missionIds: input.missionIds, confirmed: true });
    return inImmediateTransaction(this.database, () => {
      const authorities = this.assertArchiveAuthorities(input.missionIds, input.mutationAuthorities);
      const concurrentReplay = this.readIdempotency<MissionBulkArchiveResult>(
        input.actorId, "bulk-archive", input.idempotencyKey, requestHash,
      );
      if (concurrentReplay) return concurrentReplay;
      const outcomes: MissionBulkItemOutcome[] = [];
      const now = new Date().toISOString();
      for (const missionId of input.missionIds) {
        const authority = authorities.get(missionId)!;
        const mission = this.database.prepare(`
          WITH ranked AS (
            SELECT r.*, ROW_NUMBER() OVER (ORDER BY r.created_at DESC, r.id DESC) AS rank
            FROM runs r WHERE r.mission_id = ?
          )
          SELECT m.id, m.journey, m.status, r.id AS latest_run_id, r.status AS latest_run_status
          FROM missions m LEFT JOIN ranked r ON r.rank = 1 WHERE m.id = ?
        `).get(missionId, missionId) as ArchiveMissionRow | undefined;
        if (!mission || mission.latest_run_id !== authority.runId) {
          throw conflict(
            "archive_authority_scope_changed",
            "A selected mission changed after its runtime authority was established, so nothing was archived.",
            "Refresh the mission portfolio, reacquire current V2 runtime authority, and confirm the exact selection again.",
          );
        }
        const activeRuns = (this.database.prepare(`
          SELECT COUNT(*) AS count FROM runs WHERE mission_id = ? AND status NOT IN ('completed', 'failed', 'cancelled')
        `).get(missionId) as { count: number }).count;
        const activeActions = (this.database.prepare(`
          SELECT COUNT(*) AS count FROM actions WHERE mission_id = ? AND status IN ('queued', 'running')
        `).get(missionId) as { count: number }).count;
        const activeAssignments = (this.database.prepare(`
          SELECT COUNT(*) AS count FROM assignments a
          JOIN runs r ON r.id = a.run_id
          WHERE r.mission_id = ? AND a.status IN ('queued', 'active', 'blocked')
        `).get(missionId) as { count: number }).count;
        if (
          mission.status === "archived" ||
          !TERMINAL_MISSION_STATES.has(mission.status) ||
          !mission.latest_run_id ||
          !mission.latest_run_status ||
          !TERMINAL_RUN_STATES.has(mission.latest_run_status) ||
          activeRuns > 0 || activeActions > 0 || activeAssignments > 0
        ) {
          outcomes.push({
            missionId,
            status: "ineligible",
            reason: mission.status === "archived"
              ? "Mission is already archived."
              : "Mission or related work is not durably terminal.",
          });
          continue;
        }
        const terminalRunId = mission.latest_run_id;
        this.database.prepare(`
          UPDATE missions SET status = 'archived', version = version + 1, updated_at = ?
          WHERE id = ? AND status = ?
        `).run(now, missionId, mission.status);
        this.events.append({
          missionId,
          runId: terminalRunId,
          journey: mission.journey,
          eventType: "mission.archived",
          actorType: "operator",
          actorId: input.actorId,
          summary: "Operator archived a durably terminal mission",
          payload: { missionId, previousStatus: mission.status, selectionHash },
        });
        this.appendAudit({
          actorId: input.actorId,
          action: "mission.archived",
          resourceType: "mission",
          resourceId: missionId,
          reason: "Operator confirmed bounded bulk archive",
          details: { selectionHash, previousStatus: mission.status, terminalRunStatus: mission.latest_run_status },
          occurredAt: now,
          missionId,
          runId: terminalRunId,
          journey: mission.journey,
        });
        outcomes.push({ missionId, status: "archived", reason: "Durably terminal mission archived." });
      }
      const result: MissionBulkArchiveResult = {
        schemaVersion: "2.4",
        selectionHash,
        outcomes,
        archivedCount: outcomes.filter((outcome) => outcome.status === "archived").length,
      };
      this.appendAudit({
        actorId: input.actorId,
        action: "mission.bulk_archive_completed",
        resourceType: "mission_portfolio_archive",
        resourceId: selectionHash,
        reason: "Operator-confirmed bounded archive evaluated every exact selection item",
        details: {
          selectionHash,
          missionIds: [...input.missionIds],
          outcomes,
          archivedCount: result.archivedCount,
        },
        occurredAt: now,
      });
      this.storeIdempotency(input.actorId, "bulk-archive", input.idempotencyKey, requestHash, result, now);
      return result;
    });
  }

  private assertArchiveAuthorities(
    missionIds: readonly string[],
    mutationAuthorities: readonly MissionArchiveMutationAuthority[] | undefined,
  ): ReadonlyMap<string, MissionArchiveMutationAuthority> {
    if (!Array.isArray(mutationAuthorities) || mutationAuthorities.length !== missionIds.length) {
      throw conflict(
        "control_plane_lease_missing",
        "Current V2 runtime authority is required for every selected mission.",
        "Retry through the active Ti-Scale runtime controller; imported history remains read-only.",
      );
    }
    const byMission = new Map(mutationAuthorities.map((authority) => [authority.missionId, authority]));
    if (
      byMission.size !== missionIds.length
      || missionIds.some((missionId) => {
        const authority = byMission.get(missionId);
        return !authority || typeof authority.runId !== "string" || typeof authority.assertCurrent !== "function";
      })
    ) {
      throw conflict(
        "control_plane_lease_fence_invalid",
        "The selected mission set does not match the trusted runtime authority set.",
        "Refresh the portfolio and retry only through the current fenced V2 runtime controller.",
      );
    }
    for (const missionId of missionIds) byMission.get(missionId)!.assertCurrent();
    return byMission;
  }

  exportMetadata(input: {
    readonly actorId: string;
    readonly idempotencyKey: string;
    readonly missionIds: readonly string[];
  }): MissionBulkExportResult {
    validateMissionSelection(input.missionIds);
    const selectionHash = hashCanonical(input.missionIds);
    const requestHash = hashCanonical({ missionIds: input.missionIds, confirmed: true });
    const replay = this.readIdempotency<MissionBulkExportResult>(
      input.actorId, "bulk-export", input.idempotencyKey, requestHash,
    );
    if (replay) return replay;
    return inImmediateTransaction(this.database, () => {
      const concurrentReplay = this.readIdempotency<MissionBulkExportResult>(
        input.actorId, "bulk-export", input.idempotencyKey, requestHash,
      );
      if (concurrentReplay) return concurrentReplay;
      const records: MissionExportRecord[] = [];
      const outcomes: MissionBulkItemOutcome[] = [];
      for (const missionId of input.missionIds) {
        const row = this.database.prepare(`
          WITH ranked AS (
            SELECT r.*, ROW_NUMBER() OVER (ORDER BY r.created_at DESC, r.id DESC) AS rank
            FROM runs r WHERE r.mission_id = ?
          )
          SELECT m.id, m.name, m.journey, m.status, m.authorization_status,
            m.engagement_id, m.created_at, m.updated_at,
            r.id AS run_id, r.status AS run_status, r.progress,
            ps.phase, r.current_owner_id, r.started_at, r.ended_at
          FROM missions m
          LEFT JOIN ranked r ON r.rank = 1
          LEFT JOIN plan_steps ps ON ps.id = r.current_step_id
          WHERE m.id = ?
        `).get(missionId, missionId) as ExportMissionRow | undefined;
        if (!row) {
          outcomes.push({ missionId, status: "not_found", reason: "Mission does not exist." });
          continue;
        }
        const targets = this.database.prepare(`
          SELECT disposition, normalized_target FROM mission_targets WHERE mission_id = ?
          ORDER BY disposition, normalized_target
        `).all(missionId) as Array<{ disposition: string; normalized_target: string }>;
        const allowedTargetCount = targets.filter((target) => target.disposition === "allowed").length;
        const prohibitedTargetCount = targets.filter((target) => target.disposition === "prohibited").length;
        const evidenceCount = (this.database.prepare(
          "SELECT COUNT(*) AS count FROM evidence WHERE mission_id = ?",
        ).get(missionId) as { count: number }).count;
        const preview = truncate(row.name, TITLE_PREVIEW_LIMIT);
        records.push({
          missionId: row.id,
          titlePreview: preview.value,
          titleSha256: sha256(row.name),
          titleTruncated: preview.truncated,
          journey: row.journey,
          missionStatus: row.status,
          authorizationStatus: row.authorization_status,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          engagement: {
            present: row.engagement_id !== null,
            sha256: row.engagement_id ? sha256(row.engagement_id) : null,
          },
          scope: {
            allowedTargetCount,
            prohibitedTargetCount,
            targetSetSha256: hashCanonical(targets),
          },
          latestRun: row.run_id && row.run_status ? {
            id: row.run_id,
            status: row.run_status,
            progress: row.progress ?? 0,
            phase: row.phase,
            ownerId: row.current_owner_id,
            startedAt: row.started_at,
            endedAt: row.ended_at,
          } : null,
          evidenceCount,
          findingCounts: findingCounts(this.database, missionId),
        });
        outcomes.push({ missionId, status: "exported", reason: "Redacted bounded metadata exported." });
      }
      const generatedAt = new Date().toISOString();
      const unsigned = {
        schemaVersion: "2.4" as const,
        generatedAt,
        selectionHash,
        records,
        outcomes,
        policy: {
          maxBatch: MAX_BULK_MISSIONS,
          evidenceBlobsIncluded: false as const,
          confidentialPayloadsIncluded: false as const,
          titlePreviewLimit: TITLE_PREVIEW_LIMIT,
        },
      };
      const result: MissionBulkExportResult = { ...unsigned, exportSha256: hashCanonical(unsigned) };
      this.appendAudit({
        actorId: input.actorId,
        action: "mission.bulk_metadata_exported",
        resourceType: "mission_portfolio_export",
        resourceId: selectionHash,
        reason: "Operator confirmed bounded redacted mission metadata export",
        details: {
          selectionHash,
          missionIds: [...input.missionIds],
          exportedCount: records.length,
          exportSha256: result.exportSha256,
          evidenceBlobsIncluded: false,
        },
        occurredAt: generatedAt,
      });
      this.storeIdempotency(input.actorId, "bulk-export", input.idempotencyKey, requestHash, result, generatedAt);
      return result;
    });
  }
}

export const MISSION_PORTFOLIO_LIMITS = {
  savedViews: MAX_SAVED_VIEWS,
  bulkMissions: MAX_BULK_MISSIONS,
  titlePreview: TITLE_PREVIEW_LIMIT,
} as const;

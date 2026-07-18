import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { canonicalLessonMemoryNodeId } from "../learning/AttackChainLessonRepository";
import { canonicalJson, hashJson } from "../orchestration/serialization";
import { OperationsApiError, conflict, forbidden, notFound } from "./errors";
import { lessonScopeSql, missionScopeSql, sensitivitySql } from "./scope";
import { requiredSafeReason } from "./validation";
import type {
  FollowUpRunProjection,
  OperationsAccessPolicy,
  OperationsActor,
} from "./types";
import { OPERATIONS_SCHEMA_VERSION } from "./types";

interface SourceRunRow {
  readonly id: string;
  readonly mission_id: string;
  readonly mission_name: string;
  readonly engagement_id: string | null;
  readonly journey: "autonomous" | "guided";
  readonly status: string;
  readonly contract_id: string | null;
  readonly budget_json: string;
  readonly memory_scopes_json: string | null;
  readonly contract_state: string | null;
}

interface SelectedLessonRow {
  readonly id: string;
  readonly statement: string;
  readonly node_id: string;
}

interface StoredIdempotency {
  readonly requestHash: string;
  readonly response: FollowUpRunProjection;
}

function idempotencySettingKey(key: string): string {
  const digest = createHash("sha256").update(key, "utf8").digest("hex");
  return `idempotency.operations.follow_up.${digest}`;
}

function parseStringArray(value: string | null): string[] {
  try {
    const parsed = JSON.parse(value ?? "[]") as unknown;
    return Array.isArray(parsed)
      ? parsed.filter((item): item is string => typeof item === "string")
      : [];
  } catch {
    return [];
  }
}

function parseStored(value: string): StoredIdempotency | null {
  try {
    const parsed = JSON.parse(value) as StoredIdempotency;
    return parsed && typeof parsed.requestHash === "string" && parsed.response?.schemaVersion === "2.4"
      ? parsed
      : null;
  } catch {
    return null;
  }
}

/**
 * Creates another execution attempt for the same durable mission. The journey
 * and Autonomous contract cannot change here. A material objective, scope, or
 * journey change still requires a new mission or a versioned contract amendment.
 */
export class FollowUpRunRepository {
  private readonly events: EventRepository;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.events = new EventRepository(database);
  }

  create(
    sourceRunId: string,
    input: { readonly reason: string; readonly selectedLessonIds: readonly string[] },
    idempotencyKey: string,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
    assertMutationAuthority: () => void,
  ): FollowUpRunProjection {
    if (actor.type !== "operator" && actor.type !== "admin") {
      throw forbidden("Only an operator or administrator can create a follow-up run.");
    }
    // Keep the repository boundary safe even when it is called outside the
    // HTTP router. This value is copied into immutable selection and audit rows.
    const reason = requiredSafeReason(input.reason, "Follow-up reason", 2_000);
    const selectedLessonIds = [...new Set(input.selectedLessonIds)].sort();
    const requestHash = hashJson({ sourceRunId, reason, selectedLessonIds, actorId: actor.id });
    const settingKey = idempotencySettingKey(idempotencyKey);

    return inImmediateTransaction(this.database, () => {
      // The HTTP boundary establishes the trusted proof; repeat it inside the
      // atomic idempotency/write transaction so replay cannot survive lease
      // expiry, release, or controller takeover.
      assertMutationAuthority();
      const scope = missionScopeSql("m", access);
      const source = this.database.prepare(`
        SELECT r.id, r.mission_id, m.name AS mission_name, m.engagement_id,
          r.journey, r.status, r.contract_id, r.budget_json,
          mc.memory_scopes_json, mc.state AS contract_state
        FROM runs r
        JOIN missions m ON m.id = r.mission_id
        LEFT JOIN mission_contracts mc ON mc.id = r.contract_id
        WHERE r.id = ? AND ${scope.sql}
      `).get(sourceRunId, ...scope.params) as SourceRunRow | undefined;
      if (!source) throw notFound("Source run");

      // Idempotency never bypasses authorization. Re-resolve the current
      // source-run scope before returning any stored mission metadata.
      const prior = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(settingKey) as { value_json: string } | undefined;
      if (prior) {
        const stored = parseStored(prior.value_json);
        if (!stored || stored.requestHash !== requestHash) {
          throw conflict(
            "The Idempotency-Key was already used for a different follow-up request.",
            "Use a new submission key after reviewing the current terminal run and selected lessons.",
          );
        }
        return stored.response;
      }

      if (!['completed', 'failed', 'cancelled'].includes(source.status)) {
        throw conflict(
          "A follow-up run can be created only from a terminal run.",
          "Complete or cancel the current run before creating another attempt on this mission.",
        );
      }
      if (source.journey === "autonomous" && (!source.contract_id || source.contract_state !== "confirmed")) {
        throw new OperationsApiError(409, "follow_up_contract_unavailable", "The confirmed Autonomous contract is unavailable", {
          humanMessage: "This Autonomous run cannot be repeated because its confirmed contract is unavailable.",
          category: "contract",
          remediation: "Create a new Autonomous mission contract instead of bypassing the missing boundary.",
        });
      }
      const memoryScopes = parseStringArray(source.memory_scopes_json);
      if (
        source.journey === "autonomous" && selectedLessonIds.length > 0 &&
        !memoryScopes.includes("verified_lessons")
      ) {
        throw forbidden(
          "The signed Autonomous contract does not permit verified-lesson context.",
          "Create a new versioned contract that explicitly permits verified lessons.",
        );
      }

      const lessons = selectedLessonIds.map((lessonId): SelectedLessonRow => {
        const nodeId = canonicalLessonMemoryNodeId(lessonId);
        const lessonScope = lessonScopeSql("l", access);
        const visibility = sensitivitySql("mn.sensitivity", access);
        const allowFlag = source.journey === "autonomous" ? "allowAutonomous" : "allowGuided";
        const row = this.database.prepare(`
          SELECT l.id, l.statement, mn.id AS node_id
          FROM lessons l
          JOIN memory_nodes mn ON mn.id = ? AND mn.node_type = 'lesson'
          WHERE l.id = ? AND l.status = 'verified'
            AND (l.expires_at IS NULL OR l.expires_at > ?)
            AND mn.lifecycle_status = 'verified'
            AND (mn.expires_at IS NULL OR mn.expires_at > ?)
            AND COALESCE(json_extract(mn.retention_policy_json, '$.${allowFlag}'), 0) = 1
            AND ${lessonScope.sql}
            AND ${visibility.sql}
            AND (
              l.mission_id = ?
              OR (? IS NOT NULL AND l.engagement_id = ?)
              OR (l.mission_id IS NULL AND l.engagement_id IS NULL)
            )
            AND (
              mn.mission_id = ?
              OR (? IS NOT NULL AND mn.engagement_id = ?)
              OR (mn.mission_id IS NULL AND mn.engagement_id IS NULL)
            )
        `).get(
          nodeId,
          lessonId,
          this.clock().toISOString(),
          this.clock().toISOString(),
          ...lessonScope.params,
          ...visibility.params,
          source.mission_id,
          source.engagement_id,
          source.engagement_id,
          source.mission_id,
          source.engagement_id,
          source.engagement_id,
        ) as SelectedLessonRow | undefined;
        if (!row) {
          throw new OperationsApiError(409, "follow_up_lesson_ineligible", `Verified lesson is not eligible: ${lessonId}`, {
            humanMessage: "A selected lesson is no longer independently verified, reusable, or visible in this mission scope.",
            category: "memory_scope",
            details: { lessonId },
            remediation: "Remove the ineligible lesson and review the follow-up context again.",
          });
        }
        return row;
      });

      const now = this.clock().toISOString();
      const runId = `run_${randomUUID()}`;
      const statusReason = source.journey === "autonomous"
        ? "Follow-up run created under the unchanged confirmed Autonomous contract."
        : "Follow-up Guided run created; every consequential step still requires a deliberate exact decision.";
      const nextAction = source.journey === "autonomous"
        ? "Build a new in-contract plan using only the selected verified lesson context"
        : "Explain a new bounded plan and recommend the first deliberate Guided step";
      this.database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, control_plane, contract_id, progress,
          status_reason, next_action_summary, budget_json, budget_usage_json,
          retry_count, replan_count, started_at, created_at, updated_at, version
        ) VALUES (?, ?, ?, 'planning', 'ti_scale', ?, 0, ?, ?, ?, '{}', 0, 0, ?, ?, ?, 1)
      `).run(
        runId,
        source.mission_id,
        source.journey,
        source.contract_id,
        statusReason,
        nextAction,
        source.budget_json,
        now,
        now,
        now,
      );
      const insertSelection = this.database.prepare(`
        INSERT INTO run_context_selections (
          id, run_id, node_id, lesson_id, selection_type,
          selected_by, reason, selected_at
        ) VALUES (?, ?, ?, ?, 'verified_lesson', ?, ?, ?)
      `);
      for (const lesson of lessons) {
        insertSelection.run(
          `ctxsel_${randomUUID()}`,
          runId,
          lesson.node_id,
          lesson.id,
          actor.id,
          reason,
          now,
        );
      }
      this.database.prepare(`
        UPDATE missions SET status = 'active', updated_at = ? WHERE id = ?
      `).run(now, source.mission_id);

      const event = this.events.append({
        missionId: source.mission_id,
        runId,
        journey: source.journey,
        eventType: "run.follow_up_created",
        // Event actors model the operational role, while audit actors retain
        // the administrative identity. An administrator creating a run is
        // acting through the operator control plane.
        actorType: "operator",
        actorId: actor.id,
        summary: `Created a ${source.journey} follow-up run from a terminal attempt`,
        payload: {
          sourceRunId,
          selectedVerifiedLessonIds: lessons.map((lesson) => lesson.id),
          selectedContextNodeIds: lessons.map((lesson) => lesson.node_id),
          contractChanged: false,
          journeyChanged: false,
        },
        sensitivity: "private",
      });
      this.appendAudit({
        missionId: source.mission_id,
        runId,
        journey: source.journey,
        actor,
        sourceRunId,
        reason,
        lessonIds: lessons.map((lesson) => lesson.id),
        eventId: event.id,
        now,
      });

      const response: FollowUpRunProjection = {
        schemaVersion: OPERATIONS_SCHEMA_VERSION,
        sourceRunId,
        run: {
          id: runId,
          missionId: source.mission_id,
          missionName: source.mission_name,
          journey: source.journey,
          status: "planning",
          statusReason,
          nextAction,
          createdAt: now,
        },
        selectedLessons: lessons.map((lesson) => ({
          id: lesson.id,
          nodeId: lesson.node_id,
          statement: lesson.statement,
          selectionState: "eligible_for_planning",
        })),
        nextUrl: `/missions/${encodeURIComponent(source.mission_id)}/runs/${encodeURIComponent(runId)}`,
      };
      this.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'private', 1, ?, ?)
      `).run(settingKey, canonicalJson({ requestHash, response }), actor.id, now);
      return response;
    });
  }

  private appendAudit(input: {
    readonly missionId: string;
    readonly runId: string;
    readonly journey: "autonomous" | "guided";
    readonly actor: OperationsActor;
    readonly sourceRunId: string;
    readonly reason: string;
    readonly lessonIds: readonly string[];
    readonly eventId: string;
    readonly now: string;
  }): void {
    const previous = this.database.prepare(`
      SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get() as { record_hash: string } | undefined;
    const auditId = `audit_${randomUUID()}`;
    const details = {
      sourceRunId: input.sourceRunId,
      selectedVerifiedLessonIds: input.lessonIds,
      eventId: input.eventId,
      contractChanged: false,
      journeyChanged: false,
    };
    const recordHash = hashJson({
      id: auditId,
      previousHash: previous?.record_hash ?? null,
      journey: input.journey,
      actorId: input.actor.id,
      action: "run.follow_up_created",
      missionId: input.missionId,
      runId: input.runId,
      reason: input.reason,
      details,
      occurredAt: input.now,
    });
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json,
        previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'run.follow_up_created', 'run', ?, ?, ?, ?, ?, ?)
    `).run(
      auditId,
      input.missionId,
      input.runId,
      input.journey,
      input.actor.type,
      input.actor.id,
      input.runId,
      input.reason,
      canonicalJson(details),
      previous?.record_hash ?? null,
      recordHash,
      input.now,
    );
  }
}

import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type {
  OperationsAccessPolicy,
  OperationsActor,
} from "../operations/types";
import { missionScopeSql, sensitivitySql } from "../operations/scope";
import {
  canonicalJson,
  decodeCursor,
  encodeCursor,
  sha256,
} from "../operations/validation";
import { NotificationApiError } from "./NotificationApiError";
import {
  canMutateNotificationReadState,
  NOTIFICATION_SCHEMA_VERSION,
  type NotificationMutation,
  type NotificationPage,
  type NotificationProjection,
  type NotificationUnreadCount,
} from "./types";

interface NotificationRow {
  readonly id: string;
  readonly notification_type: string;
  readonly severity: NotificationProjection["severity"];
  readonly title: string;
  readonly body: string;
  readonly actor_read_at: string | null;
  readonly created_at: string;
  readonly event_id: string;
  readonly event_type: string;
  readonly sensitivity: NotificationProjection["sensitivity"];
  readonly mission_id: string;
  readonly mission_name: string;
  readonly engagement_id: string | null;
  readonly run_id: string;
  readonly journey: "autonomous" | "guided";
}

interface StoredMutation {
  readonly requestHash: string;
  readonly response: NotificationMutation;
}

function deepLink(row: NotificationRow): string {
  if (row.notification_type === "memory_candidate_ready") return "/brain/inbox";
  if (row.notification_type === "vault_conflict") return "/brain/vault";
  if (row.notification_type === "guided_decision_ready" || row.notification_type === "guided_recovery_ready") {
    return `/guided/${encodeURIComponent(row.mission_id)}`;
  }
  if (row.notification_type === "approval_requested") return "/decisions";
  return row.journey === "autonomous"
    ? `/live/${encodeURIComponent(row.run_id)}`
    : `/missions/${encodeURIComponent(row.mission_id)}/runs/${encodeURIComponent(row.run_id)}`;
}

function mapRow(row: NotificationRow): NotificationProjection {
  return {
    id: row.id,
    eventId: row.event_id,
    eventType: row.event_type,
    notificationType: row.notification_type,
    severity: row.severity,
    title: row.title,
    body: row.body,
    mission: {
      id: row.mission_id,
      name: row.mission_name,
      engagementId: row.engagement_id,
    },
    run: { id: row.run_id, journey: row.journey },
    sensitivity: row.sensitivity,
    deepLink: deepLink(row),
    readAt: row.actor_read_at,
    createdAt: row.created_at,
  };
}

function settingKey(actor: OperationsActor, operation: string, key: string): string {
  return `idempotency.notifications.${operation}.${sha256(`${actor.type}\u0000${actor.id}\u0000${key}`)}`;
}

function normalizedAccessScope(access: OperationsAccessPolicy): Record<string, unknown> {
  return {
    maximumSensitivity: access.maximumSensitivity,
    allEngagements: access.allEngagements === true,
    engagementIds: [...new Set(access.engagementIds ?? [])].sort(),
    missionIds: [...new Set(access.missionIds ?? [])].sort(),
  };
}

function cursorClause(cursor: ReturnType<typeof decodeCursor>): {
  readonly sql: string;
  readonly params: readonly unknown[];
} {
  return cursor
    ? {
        sql: "(n.created_at < ? OR (n.created_at = ? AND n.id < ?))",
        params: [cursor.sort, cursor.sort, cursor.id],
      }
    : { sql: "1", params: [] };
}

/** Scope-checked canonical notification reads and idempotent read-state writes. */
export class NotificationRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  list(
    access: OperationsAccessPolicy,
    actor: OperationsActor,
    options: { readonly limit: number; readonly cursor?: string; readonly state?: "all" | "unread" | "read" },
  ): NotificationPage {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const page = cursorClause(decodeCursor(options.cursor));
    const state = options.state ?? "all";
    const rows = this.database.prepare(`
      SELECT n.*, receipt.read_at AS actor_read_at,
        e.id AS event_id, e.event_type, e.sensitivity,
        m.id AS mission_id, m.name AS mission_name, m.engagement_id,
        r.id AS run_id, r.journey
      FROM notifications n
      LEFT JOIN notification_read_receipts receipt
        ON receipt.notification_id = n.id
        AND receipt.actor_type = ? AND receipt.actor_id = ?
      JOIN events e ON e.id = substr(n.id, 14)
      JOIN missions m ON m.id = n.mission_id AND m.id = e.mission_id
      JOIN runs r ON r.id = n.run_id AND r.id = e.run_id
      WHERE ${scope.sql} AND ${sensitivity.sql} AND ${page.sql}
        ${state === "unread" ? "AND receipt.read_at IS NULL" : state === "read" ? "AND receipt.read_at IS NOT NULL" : ""}
      ORDER BY n.created_at DESC, n.id DESC
      LIMIT ?
    `).all(
      actor.type,
      actor.id,
      ...scope.params,
      ...sensitivity.params,
      ...page.params,
      options.limit + 1,
    ) as NotificationRow[];
    const hasMore = rows.length > options.limit;
    const visible = hasMore ? rows.slice(0, options.limit) : rows;
    const last = visible.at(-1);
    return {
      schemaVersion: NOTIFICATION_SCHEMA_VERSION,
      items: visible.map(mapRow),
      nextCursor: hasMore && last ? encodeCursor(last.created_at, last.id) : null,
    };
  }

  unreadCount(access: OperationsAccessPolicy, actor: OperationsActor): NotificationUnreadCount {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const row = this.database.prepare(`
      SELECT COUNT(*) AS count
      FROM notifications n
      LEFT JOIN notification_read_receipts receipt
        ON receipt.notification_id = n.id
        AND receipt.actor_type = ? AND receipt.actor_id = ?
      JOIN events e ON e.id = substr(n.id, 14)
      JOIN missions m ON m.id = n.mission_id AND m.id = e.mission_id
      JOIN runs r ON r.id = n.run_id AND r.id = e.run_id
      WHERE receipt.read_at IS NULL AND ${scope.sql} AND ${sensitivity.sql}
    `).get(actor.type, actor.id, ...scope.params, ...sensitivity.params) as { count: number };
    return { schemaVersion: NOTIFICATION_SCHEMA_VERSION, unreadCount: Number(row.count) };
  }

  markRead(
    notificationId: string,
    access: OperationsAccessPolicy,
    actor: OperationsActor,
    idempotencyKey: string,
  ): NotificationMutation {
    this.requireHumanMutationActor(actor);
    return inImmediateTransaction(this.database, () => {
      // Authorization is re-evaluated before idempotency replay so a retained
      // response can never become a notification-existence or scope oracle.
      const row = this.requireVisible(notificationId, access, actor);
      const requestHash = sha256(canonicalJson({ notificationId }));
      const key = settingKey(actor, "mark-read", idempotencyKey);
      const replay = this.replay(key, requestHash);
      if (replay) return replay;
      const readAt = row.actor_read_at ?? this.clock().toISOString();
      const changed = row.actor_read_at === null
        ? this.database.prepare(`
            INSERT OR IGNORE INTO notification_read_receipts (
              notification_id, actor_type, actor_id, read_at
            ) VALUES (?, ?, ?, ?)
          `).run(notificationId, actor.type, actor.id, readAt).changes
        : 0;
      const response: NotificationMutation = {
        schemaVersion: NOTIFICATION_SCHEMA_VERSION,
        mutation: {
          kind: "mark_read",
          notificationId,
          changedCount: changed,
          readAt,
        },
      };
      if (changed === 1) this.appendAudit(actor, row, "notification.marked_read", readAt, 1);
      this.remember(key, requestHash, response, actor.id, readAt);
      return response;
    });
  }

  markAllRead(
    access: OperationsAccessPolicy,
    actor: OperationsActor,
    idempotencyKey: string,
  ): NotificationMutation {
    this.requireHumanMutationActor(actor);
    return inImmediateTransaction(this.database, () => {
      const requestHash = sha256(canonicalJson({
        scope: "authorized_unread",
        access: normalizedAccessScope(access),
      }));
      const key = settingKey(actor, "mark-all-read", idempotencyKey);
      const replay = this.replay(key, requestHash);
      if (replay) return replay;
      const scope = missionScopeSql("m", access);
      const sensitivity = sensitivitySql("e.sensitivity", access);
      const readAt = this.clock().toISOString();
      // One scope-checked subquery stays below SQLite's bind limit regardless
      // of inbox size and updates exactly the records authorized at commit.
      const changedCount = this.database.prepare(`
        INSERT OR IGNORE INTO notification_read_receipts (
          notification_id, actor_type, actor_id, read_at
        )
        SELECT n.id, ?, ?, ?
        FROM notifications n
        LEFT JOIN notification_read_receipts receipt
          ON receipt.notification_id = n.id
          AND receipt.actor_type = ? AND receipt.actor_id = ?
        JOIN events e ON e.id = substr(n.id, 14)
        JOIN missions m ON m.id = n.mission_id AND m.id = e.mission_id
        JOIN runs r ON r.id = n.run_id AND r.id = e.run_id
        WHERE receipt.notification_id IS NULL AND ${scope.sql} AND ${sensitivity.sql}
      `).run(
        actor.type,
        actor.id,
        readAt,
        actor.type,
        actor.id,
        ...scope.params,
        ...sensitivity.params,
      ).changes;
      const response: NotificationMutation = {
        schemaVersion: NOTIFICATION_SCHEMA_VERSION,
        mutation: {
          kind: "mark_all_read",
          notificationId: null,
          changedCount,
          readAt,
        },
      };
      if (changedCount > 0) this.appendScopeAudit(actor, "notification.marked_all_read", readAt, changedCount);
      this.remember(key, requestHash, response, actor.id, readAt);
      return response;
    });
  }

  private requireVisible(
    notificationId: string,
    access: OperationsAccessPolicy,
    actor: OperationsActor,
  ): NotificationRow {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const row = this.database.prepare(`
      SELECT n.*, receipt.read_at AS actor_read_at,
        e.id AS event_id, e.event_type, e.sensitivity,
        m.id AS mission_id, m.name AS mission_name, m.engagement_id,
        r.id AS run_id, r.journey
      FROM notifications n
      LEFT JOIN notification_read_receipts receipt
        ON receipt.notification_id = n.id
        AND receipt.actor_type = ? AND receipt.actor_id = ?
      JOIN events e ON e.id = substr(n.id, 14)
      JOIN missions m ON m.id = n.mission_id AND m.id = e.mission_id
      JOIN runs r ON r.id = n.run_id AND r.id = e.run_id
      WHERE n.id = ? AND ${scope.sql} AND ${sensitivity.sql}
    `).get(
      actor.type,
      actor.id,
      notificationId,
      ...scope.params,
      ...sensitivity.params,
    ) as NotificationRow | undefined;
    if (!row) {
      throw new NotificationApiError(
        404,
        "notification_not_found",
        "Notification was not found",
        "The notification does not exist or is outside your authorized scope.",
        "not_found",
      );
    }
    return row;
  }

  private requireHumanMutationActor(actor: OperationsActor): void {
    if (canMutateNotificationReadState(actor)) return;
    throw new NotificationApiError(
      403,
      "notification_read_state_forbidden",
      "Only a human reviewer may update notification read state",
      "Only an operator, reviewer, or administrator can mark notifications as read.",
      "policy_denied",
      "Use an authenticated human review identity for this mutation.",
    );
  }

  private replay(key: string, requestHash: string): NotificationMutation | undefined {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(key) as { value_json: string } | undefined;
    if (!row) return undefined;
    const value = JSON.parse(row.value_json) as StoredMutation;
    if (value.requestHash !== requestHash || !value.response) {
      throw new NotificationApiError(
        409,
        "notification_idempotency_conflict",
        "Idempotency key was already used for a different request",
        "Use a new Idempotency-Key for a materially different notification mutation.",
        "conflict",
      );
    }
    return value.response;
  }

  private remember(
    key: string,
    requestHash: string,
    response: NotificationMutation,
    actorId: string,
    now: string,
  ): void {
    this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'restricted', 1, ?, ?)
    `).run(key, canonicalJson({ requestHash, response }), actorId, now);
  }

  private appendAudit(
    actor: OperationsActor,
    row: NotificationRow,
    action: string,
    occurredAt: string,
    changedCount: number,
  ): void {
    this.insertAudit({
      actor,
      missionId: row.mission_id,
      runId: row.run_id,
      journey: row.journey,
      action,
      resourceId: row.id,
      occurredAt,
      changedCount,
    });
  }

  private appendScopeAudit(
    actor: OperationsActor,
    action: string,
    occurredAt: string,
    changedCount: number,
  ): void {
    this.insertAudit({
      actor,
      missionId: null,
      runId: null,
      journey: null,
      action,
      resourceId: null,
      occurredAt,
      changedCount,
    });
  }

  private insertAudit(input: {
    readonly actor: OperationsActor;
    readonly missionId: string | null;
    readonly runId: string | null;
    readonly journey: "autonomous" | "guided" | null;
    readonly action: string;
    readonly resourceId: string | null;
    readonly occurredAt: string;
    readonly changedCount: number;
  }): void {
    const previous = this.database.prepare(
      "SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1",
    ).get() as { record_hash: string } | undefined;
    const id = `audit_${randomUUID()}`;
    const details = { channel: "in_app_only", changedCount: input.changedCount };
    const hashInput = {
      id,
      missionId: input.missionId,
      runId: input.runId,
      journey: input.journey,
      actorType: input.actor.type,
      actorId: input.actor.id,
      action: input.action,
      resourceType: "notification",
      resourceId: input.resourceId,
      reason: "Operator updated in-app notification read state",
      details,
      previousHash: previous?.record_hash ?? null,
      occurredAt: input.occurredAt,
    };
    const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(hashInput)}`);
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json,
        previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'notification', ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      input.missionId,
      input.runId,
      input.journey,
      input.actor.type,
      input.actor.id,
      input.action,
      input.resourceId,
      "Operator updated in-app notification read state",
      canonicalJson(details),
      previous?.record_hash ?? null,
      recordHash,
      input.occurredAt,
    );
  }
}

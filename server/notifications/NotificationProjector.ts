import { notificationDefinitionFor } from "../../src/domain/notificationEventRegistry";
import type { SqliteDatabase } from "../db";
import type { RunEvent } from "../events/types";

/**
 * Project only explicitly recognized semantic events. Notification content is
 * fixed by the shared event registry: payloads, provider output, tool output,
 * and event summaries are intentionally never copied into this user-facing
 * store.
 */
export class NotificationProjector {
  private readonly insert;

  constructor(database: SqliteDatabase) {
    this.insert = database.prepare(`
      INSERT OR IGNORE INTO notifications (
        id, mission_id, run_id, notification_type, severity,
        title, body, read_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
    `);
  }

  project(event: RunEvent): boolean {
    const definition = notificationDefinitionFor(event.eventType, event.journey);
    if (!definition) return false;
    return this.insert.run(
      `notification:${event.id}`,
      event.missionId,
      event.runId,
      definition.notificationType,
      definition.severity,
      definition.title,
      definition.body,
      event.occurredAt,
    ).changes === 1;
  }
}

export { isActionableNotificationEvent } from "../../src/domain/notificationEventRegistry";

import type {
  InAppNotification,
  NotificationMutation,
  NotificationPage,
  NotificationUnreadCount,
} from "../types/notifications";
import { array, nonEmpty, nullableString, number, object, schema } from "./common";

function choice<const T extends string>(value: unknown, choices: readonly T[], label: string): T {
  if (typeof value === "string" && choices.includes(value as T)) return value as T;
  throw new Error(`${label} is invalid`);
}

function nonNegativeInteger(value: unknown, label: string): number {
  const result = number(value, label);
  if (!Number.isSafeInteger(result) || result < 0) throw new Error(`${label} must be a non-negative integer`);
  return result;
}

function safeDeepLink(value: unknown): string {
  const link = nonEmpty(value, "notification.deepLink");
  if (!link.startsWith("/") || link.startsWith("//") || link.includes("\\")) {
    throw new Error("notification deep link is invalid");
  }
  return link;
}

function parseNotification(value: unknown): InAppNotification {
  const item = object(value, "notification");
  const mission = object(item.mission, "notification.mission");
  const run = object(item.run, "notification.run");
  return {
    id: nonEmpty(item.id, "notification.id"),
    eventId: nonEmpty(item.eventId, "notification.eventId"),
    eventType: nonEmpty(item.eventType, "notification.eventType"),
    notificationType: nonEmpty(item.notificationType, "notification.notificationType"),
    severity: choice(item.severity, ["info", "warning", "error", "critical"] as const, "notification.severity"),
    title: nonEmpty(item.title, "notification.title"),
    body: nonEmpty(item.body, "notification.body"),
    mission: {
      id: nonEmpty(mission.id, "notification.mission.id"),
      name: nonEmpty(mission.name, "notification.mission.name"),
      engagementId: nullableString(mission.engagementId, "notification.mission.engagementId"),
    },
    run: {
      id: nonEmpty(run.id, "notification.run.id"),
      journey: choice(run.journey, ["autonomous", "guided"] as const, "notification.run.journey"),
    },
    sensitivity: choice(
      item.sensitivity,
      ["public", "internal", "private", "restricted"] as const,
      "notification.sensitivity",
    ),
    deepLink: safeDeepLink(item.deepLink),
    readAt: nullableString(item.readAt, "notification.readAt"),
    createdAt: nonEmpty(item.createdAt, "notification.createdAt"),
  };
}
export function parseNotificationPage(payload: unknown): NotificationPage {
  const root = object(payload, "notification page");
  schema(root);
  return {
    schemaVersion: "2.4",
    items: array(root.items, "notification items").map(parseNotification),
    nextCursor: nullableString(root.nextCursor, "notification nextCursor"),
  };
}

export function parseNotificationUnreadCount(payload: unknown): NotificationUnreadCount {
  const root = object(payload, "notification unread count");
  schema(root);
  return { schemaVersion: "2.4", unreadCount: nonNegativeInteger(root.unreadCount, "unreadCount") };
}

export function parseNotificationMutation(payload: unknown): NotificationMutation {
  const root = object(payload, "notification mutation");
  schema(root);
  const mutation = object(root.mutation, "notification mutation value");
  const kind = choice(mutation.kind, ["mark_read", "mark_all_read"] as const, "notification mutation kind");
  const notificationId = nullableString(mutation.notificationId, "notification mutation notificationId");
  if ((kind === "mark_read") !== (notificationId !== null)) {
    throw new Error("notification mutation identity does not match its kind");
  }
  return {
    schemaVersion: "2.4",
    mutation: {
      kind,
      notificationId,
      changedCount: nonNegativeInteger(mutation.changedCount, "notification changedCount"),
      readAt: nonEmpty(mutation.readAt, "notification readAt"),
    },
  };
}

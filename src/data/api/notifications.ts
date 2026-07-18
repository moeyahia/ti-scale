import {
  parseNotificationMutation,
  parseNotificationPage,
  parseNotificationUnreadCount,
} from "../../domain/schemas/notifications";
import type {
  NotificationMutation,
  NotificationPage,
  NotificationUnreadCount,
} from "../../domain/types/notifications";
import { apiRequest } from "./client";

const ROOT = "/api/v2/notifications";

function mutationKey(prefix: string): string {
  return globalThis.crypto?.randomUUID?.() ?? `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function fetchNotifications(
  signal?: AbortSignal,
  options: { readonly state?: "all" | "unread" | "read"; readonly limit?: number; readonly cursor?: string } = {},
): Promise<NotificationPage> {
  const query = new URLSearchParams();
  if (options.state) query.set("state", options.state);
  if (options.limit) query.set("limit", String(options.limit));
  if (options.cursor) query.set("cursor", options.cursor);
  return apiRequest(`${ROOT}${query.size ? `?${query}` : ""}`, {
    method: "GET",
    signal,
    parse: parseNotificationPage,
  });
}
export function fetchNotificationUnreadCount(signal?: AbortSignal): Promise<NotificationUnreadCount> {
  return apiRequest(`${ROOT}/unread-count`, {
    method: "GET",
    signal,
    parse: parseNotificationUnreadCount,
  });
}

export function markNotificationRead(
  notificationId: string,
  idempotencyKey = mutationKey("notification-read"),
): Promise<NotificationMutation> {
  return apiRequest(`${ROOT}/${encodeURIComponent(notificationId)}/read`, {
    method: "POST",
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({}),
    parse: parseNotificationMutation,
  });
}

export function markAllNotificationsRead(
  idempotencyKey = mutationKey("notification-read-all"),
): Promise<NotificationMutation> {
  return apiRequest(`${ROOT}/read-all`, {
    method: "POST",
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({}),
    parse: parseNotificationMutation,
  });
}

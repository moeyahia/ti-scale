export type NotificationSeverity = "info" | "warning" | "error" | "critical";

export interface InAppNotification {
  id: string;
  eventId: string;
  eventType: string;
  notificationType: string;
  severity: NotificationSeverity;
  title: string;
  body: string;
  mission: { id: string; name: string; engagementId: string | null };
  run: { id: string; journey: "autonomous" | "guided" };
  sensitivity: "public" | "internal" | "private" | "restricted";
  deepLink: string;
  readAt: string | null;
  createdAt: string;
}

export interface NotificationPage {
  schemaVersion: "2.4";
  items: InAppNotification[];
  nextCursor: string | null;
}

export interface NotificationUnreadCount {
  schemaVersion: "2.4";
  unreadCount: number;
}

export interface NotificationMutation {
  schemaVersion: "2.4";
  mutation: {
    kind: "mark_read" | "mark_all_read";
    notificationId: string | null;
    changedCount: number;
    readAt: string;
  };
}

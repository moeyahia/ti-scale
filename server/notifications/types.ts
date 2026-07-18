import type { Request } from "express";
import type { SqliteDatabase } from "../db";
import type {
  OperationsAccessPolicy,
  OperationsActor,
} from "../operations/types";

export const NOTIFICATION_SCHEMA_VERSION = "2.4" as const;

export const HUMAN_NOTIFICATION_ACTOR_TYPES = Object.freeze([
  "operator",
  "reviewer",
  "admin",
] as const);

export function canMutateNotificationReadState(actor: OperationsActor): boolean {
  return HUMAN_NOTIFICATION_ACTOR_TYPES.includes(
    actor.type as (typeof HUMAN_NOTIFICATION_ACTOR_TYPES)[number],
  );
}

export type NotificationSeverity = "info" | "warning" | "error" | "critical";

export interface NotificationProjection {
  readonly id: string;
  readonly eventId: string;
  readonly eventType: string;
  readonly notificationType: string;
  readonly severity: NotificationSeverity;
  readonly title: string;
  readonly body: string;
  readonly mission: {
    readonly id: string;
    readonly name: string;
    readonly engagementId: string | null;
  };
  readonly run: {
    readonly id: string;
    readonly journey: "autonomous" | "guided";
  };
  readonly sensitivity: "public" | "internal" | "private" | "restricted";
  readonly deepLink: string;
  readonly readAt: string | null;
  readonly createdAt: string;
}

export interface NotificationPage {
  readonly schemaVersion: typeof NOTIFICATION_SCHEMA_VERSION;
  readonly items: readonly NotificationProjection[];
  readonly nextCursor: string | null;
}

export interface NotificationUnreadCount {
  readonly schemaVersion: typeof NOTIFICATION_SCHEMA_VERSION;
  readonly unreadCount: number;
}

export interface NotificationMutation {
  readonly schemaVersion: typeof NOTIFICATION_SCHEMA_VERSION;
  readonly mutation: {
    readonly kind: "mark_read" | "mark_all_read";
    readonly notificationId: string | null;
    readonly changedCount: number;
    readonly readAt: string;
  };
}

export interface NotificationRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (request: Request) => OperationsActor;
  readonly resolveAccess: (
    request: Request,
    actor: OperationsActor,
  ) => OperationsAccessPolicy;
  readonly clock?: () => Date;
}

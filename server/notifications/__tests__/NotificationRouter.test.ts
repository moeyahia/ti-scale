import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { EventRepository } from "../../events";
import type { OperationsAccessPolicy, OperationsActor } from "../../operations/types";
import { NotificationProjector } from "../NotificationProjector";
import { NotificationRepository } from "../NotificationRepository";
import { createNotificationRouter } from "../NotificationRouter";

type Database = ReturnType<typeof createDatabaseConnection>;
const servers: Server[] = [];
const NOW = "2026-07-15T19:00:00.000Z";

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

function addMission(database: Database, input: {
  missionId: string;
  runId: string;
  journey: "autonomous" | "guided";
  engagementId: string;
  status?: string;
}): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Bounded notification fixture', ?, 'active', 'verified', ?, 'operator', ?, ?)
  `).run(input.missionId, `Mission ${input.missionId}`, input.journey, input.engagementId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 0.5, ?, ?)
  `).run(
    input.runId,
    input.missionId,
    input.journey,
    input.status ?? (input.journey === "guided" ? "waiting_guided_decision" : "blocked"),
    NOW,
    NOW,
  );
}

function append(database: Database, input: {
  id: string;
  missionId: string;
  runId: string;
  journey: "autonomous" | "guided";
  eventType: string;
  sensitivity?: "public" | "internal" | "private" | "restricted";
}): ReturnType<EventRepository["append"]> {
  return new EventRepository(database).append({
    id: input.id,
    missionId: input.missionId,
    runId: input.runId,
    journey: input.journey,
    eventType: input.eventType,
    actorType: "system",
    summary: "Bearer must-not-leak and raw provider output must-not-leak",
    payload: {
      authorization: "Bearer must-not-leak",
      providerOutput: "raw tool content must-not-leak",
    },
    sensitivity: input.sensitivity ?? "private",
    occurredAt: NOW,
  });
}

function fixture(): Database {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  addMission(database, {
    missionId: "mission-a-auto", runId: "run-a-auto", journey: "autonomous", engagementId: "eng-a",
  });
  addMission(database, {
    missionId: "mission-a-guided", runId: "run-a-guided", journey: "guided", engagementId: "eng-a",
  });
  addMission(database, {
    missionId: "mission-b-auto", runId: "run-b-auto", journey: "autonomous", engagementId: "eng-b",
  });
  append(database, {
    id: "event-a-safe-stop", missionId: "mission-a-auto", runId: "run-a-auto",
    journey: "autonomous", eventType: "run.autonomous_safe_stopped",
  });
  append(database, {
    id: "event-a-guided", missionId: "mission-a-guided", runId: "run-a-guided",
    journey: "guided", eventType: "guided.decision_requested", sensitivity: "internal",
  });
  append(database, {
    id: "event-b-hidden", missionId: "mission-b-auto", runId: "run-b-auto",
    journey: "autonomous", eventType: "run.recovery_blocked", sensitivity: "restricted",
  });
  append(database, {
    id: "event-a-noise", missionId: "mission-a-auto", runId: "run-a-auto",
    journey: "autonomous", eventType: "tool.completed",
  });
  return database;
}

async function application() {
  const database = fixture();
  let currentActor: OperationsActor = { id: "operator-a", type: "operator" };
  let access: OperationsAccessPolicy = {
    maximumSensitivity: "private",
    engagementIds: ["eng-a"],
    missionIds: [],
  };
  const app = express();
  app.use(express.json({ limit: "32kb" }));
  app.use(createNotificationRouter({
    database,
    clock: () => new Date(NOW),
    resolveActor: () => currentActor,
    resolveAccess: () => access,
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    setActor: (next: OperationsActor) => { currentActor = next; },
    setAccess: (next: OperationsAccessPolicy) => { access = next; },
  };
}

describe("canonical in-app notifications", () => {
  test("projects recognized events atomically, redacts by construction, and ignores malformed/noise events", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    try {
      addMission(database, {
        missionId: "mission-atomic", runId: "run-atomic", journey: "autonomous", engagementId: "eng-a",
      });
      const event = append(database, {
        id: "event-atomic", missionId: "mission-atomic", runId: "run-atomic",
        journey: "autonomous", eventType: "run.recovery_blocked",
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM events WHERE id = ?").get(event.id)).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM event_outbox WHERE event_id = ?").get(event.id)).toEqual({ count: 1 });
      const notification = database.prepare("SELECT title, body FROM notifications WHERE id = ?")
        .get(`notification:${event.id}`) as { title: string; body: string };
      expect(notification).toEqual({
        title: "Run recovery blocked",
        body: "Bounded recovery could not continue safely and requires operator review.",
      });
      expect(JSON.stringify(notification)).not.toContain("must-not-leak");
      expect(new NotificationProjector(database).project(event)).toBeFalse();
      expect(database.prepare("SELECT COUNT(*) AS count FROM notifications").get()).toEqual({ count: 1 });

      const malformed = append(database, {
        id: "event-malformed-journey", missionId: "mission-atomic", runId: "run-atomic",
        journey: "autonomous", eventType: "guided.decision_requested",
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM events WHERE id = ?").get(malformed.id)).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM notifications WHERE id = ?")
        .get(`notification:${malformed.id}`)).toEqual({ count: 0 });

      addMission(database, {
        missionId: "mission-guided-mismatch", runId: "run-guided-mismatch",
        journey: "guided", engagementId: "eng-a",
      });
      const guidedSafeStop = append(database, {
        id: "event-guided-safe-stop", missionId: "mission-guided-mismatch", runId: "run-guided-mismatch",
        journey: "guided", eventType: "run.safe_stopped",
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM notifications WHERE id = ?")
        .get(`notification:${guidedSafeStop.id}`)).toEqual({ count: 0 });
      const autonomousGuidedBlock = append(database, {
        id: "event-autonomous-guided-block", missionId: "mission-atomic", runId: "run-atomic",
        journey: "autonomous", eventType: "run.guided_blocked",
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM notifications WHERE id = ?")
        .get(`notification:${autonomousGuidedBlock.id}`)).toEqual({ count: 0 });
      const guidedCompletion = append(database, {
        id: "event-guided-completed", missionId: "mission-guided-mismatch", runId: "run-guided-mismatch",
        journey: "guided", eventType: "run.completed",
      });
      expect(database.prepare("SELECT title FROM notifications WHERE id = ?")
        .get(`notification:${guidedCompletion.id}`)).toEqual({ title: "Run completed" });

      database.exec(`
        CREATE TRIGGER reject_notification_test BEFORE INSERT ON notifications
        BEGIN SELECT RAISE(ABORT, 'notification projection failure'); END;
      `);
      expect(() => append(database, {
        id: "event-rollback", missionId: "mission-atomic", runId: "run-atomic",
        journey: "autonomous", eventType: "run.autonomous_safe_stopped",
      })).toThrow("notification projection failure");
      expect(database.prepare("SELECT COUNT(*) AS count FROM events WHERE id = 'event-rollback'").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM event_outbox WHERE event_id = 'event-rollback'").get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("lists by cursor and unread count without crossing engagement or sensitivity scope", async () => {
    const { database, url } = await application();
    try {
      const first = await fetch(`${url}/api/v2/notifications?state=unread&limit=1`, {
        headers: { "X-Request-ID": "notification-list-request" },
      });
      expect(first.status).toBe(200);
      expect(first.headers.get("x-request-id")).toBe("notification-list-request");
      const firstPage = await first.json() as any;
      expect(firstPage.items).toHaveLength(1);
      expect(firstPage.nextCursor).toBeString();
      const secondPage = await (await fetch(
        `${url}/api/v2/notifications?state=unread&limit=1&cursor=${encodeURIComponent(firstPage.nextCursor)}`,
      )).json() as any;
      expect(secondPage.items).toHaveLength(1);
      const visible = [...firstPage.items, ...secondPage.items];
      expect(visible.map((item: any) => item.eventId).sort()).toEqual(["event-a-guided", "event-a-safe-stop"]);
      expect(JSON.stringify(visible)).not.toContain("must-not-leak");
      expect(JSON.stringify(visible)).not.toContain("providerOutput");
      expect(JSON.stringify(visible)).not.toContain("event-b-hidden");
      expect(visible.find((item: any) => item.eventId === "event-a-guided")).toMatchObject({
        deepLink: "/guided/mission-a-guided",
        run: { journey: "guided" },
        sensitivity: "internal",
      });
      expect(await (await fetch(`${url}/api/v2/notifications/unread-count`)).json()).toEqual({
        schemaVersion: "2.4", unreadCount: 2,
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM notifications").get()).toEqual({ count: 3 });

      const hidden = await fetch(`${url}/api/v2/notifications/notification:event-b-hidden/read`, {
        method: "POST", headers: {
          "Idempotency-Key": "hidden-notification-read-01",
          "X-Request-ID": "notification-hidden-request",
        },
      });
      expect(hidden.status).toBe(404);
      expect(hidden.headers.get("x-request-id")).toBe("notification-hidden-request");
      expect(await hidden.json()).toMatchObject({
        error: {
          code: "notification_not_found", category: "not_found", retryable: false,
          traceId: "notification-hidden-request", timestamp: expect.any(String),
        },
      });

      const invalid = await fetch(`${url}/api/v2/notifications?state=provider-output`, {
        headers: { "X-Request-ID": "notification-invalid-filter" },
      });
      expect(invalid.status).toBe(400);
      expect(await invalid.json()).toMatchObject({
        error: {
          code: "invalid_notification_state", category: "invalid_input",
          traceId: "notification-invalid-filter", retryable: false,
        },
      });

      for (const [path, code] of [
        ["/api/v2/notifications?limit=0", "invalid_pagination"],
        ["/api/v2/notifications?cursor=not-a-valid-cursor", "invalid_cursor"],
      ] as const) {
        const response = await fetch(`${url}${path}`);
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({
          error: { code, category: "invalid_input", retryable: false },
        });
      }
      const missingKey = await fetch(`${url}/api/v2/notifications/notification:event-a-safe-stop/read`, {
        method: "POST",
      });
      expect(missingKey.status).toBe(400);
      expect(await missingKey.json()).toMatchObject({
        error: { code: "idempotency_key_required", category: "invalid_input", retryable: false },
      });
    } finally {
      database.close();
    }
  });

  test("marks one and all authorized notifications read idempotently with actor audit", async () => {
    const { database, url } = await application();
    try {
      const markOne = () => fetch(`${url}/api/v2/notifications/notification:event-a-safe-stop/read`, {
        method: "POST",
        headers: {
          "Idempotency-Key": "notification-read-safe-stop-01",
          "X-Request-ID": "notification-read-request",
        },
      });
      const first = await markOne();
      expect(first.status).toBe(200);
      expect(first.headers.get("x-request-id")).toBe("notification-read-request");
      const firstPayload = await first.json();
      expect(firstPayload).toMatchObject({
        schemaVersion: "2.4",
        mutation: { kind: "mark_read", changedCount: 1, notificationId: "notification:event-a-safe-stop" },
      });
      expect(await (await markOne()).json()).toEqual(firstPayload);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'notification.marked_read' AND actor_id = 'operator-a'
      `).get()).toEqual({ count: 1 });

      const markAll = () => fetch(`${url}/api/v2/notifications/read-all`, {
        method: "POST", headers: { "Idempotency-Key": "notification-read-all-eng-a-01" },
      });
      const allPayload = await (await markAll()).json() as any;
      expect(allPayload.mutation).toMatchObject({ kind: "mark_all_read", changedCount: 1, notificationId: null });
      expect(await (await markAll()).json()).toEqual(allPayload);
      expect(await (await fetch(`${url}/api/v2/notifications/unread-count`)).json()).toEqual({
        schemaVersion: "2.4", unreadCount: 0,
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM notification_read_receipts
        WHERE notification_id = 'notification:event-b-hidden'
      `).get()).toEqual({ count: 0 });
      expect(database.prepare(`
        SELECT actor_id, details_json FROM audit_records
        WHERE action = 'notification.marked_all_read'
      `).get()).toEqual({
        actor_id: "operator-a",
        details_json: '{"changedCount":1,"channel":"in_app_only"}',
      });
    } finally {
      database.close();
    }
  });

  test("isolates list, count, and read receipts by resolved actor and denies automated mutations", async () => {
    const { database, url, setActor } = await application();
    try {
      const markForOperator = await fetch(`${url}/api/v2/notifications/notification:event-a-safe-stop/read`, {
        method: "POST",
        headers: { "Idempotency-Key": "notification-shared-actor-key-01" },
      });
      expect(markForOperator.status).toBe(200);
      expect(await (await fetch(`${url}/api/v2/notifications/unread-count`)).json()).toMatchObject({
        unreadCount: 1,
      });

      setActor({ id: "reviewer-b", type: "reviewer" });
      expect(await (await fetch(`${url}/api/v2/notifications/unread-count`)).json()).toMatchObject({
        unreadCount: 2,
      });
      const reviewerList = await (await fetch(`${url}/api/v2/notifications?limit=10`)).json() as any;
      expect(reviewerList.items.find((item: any) => item.id === "notification:event-a-safe-stop")?.readAt)
        .toBeNull();
      const reviewerSameKey = await fetch(`${url}/api/v2/notifications/notification:event-a-safe-stop/read`, {
        method: "POST",
        headers: { "Idempotency-Key": "notification-shared-actor-key-01" },
      });
      expect(reviewerSameKey.status).toBe(200);
      expect(await reviewerSameKey.json()).toMatchObject({ mutation: { changedCount: 1 } });
      const reviewerMarkAll = await fetch(`${url}/api/v2/notifications/read-all`, {
        method: "POST",
        headers: { "Idempotency-Key": "notification-actor-b-read-all-01" },
      });
      expect(await reviewerMarkAll.json()).toMatchObject({ mutation: { changedCount: 1 } });
      expect(await (await fetch(`${url}/api/v2/notifications/unread-count`)).json()).toMatchObject({
        unreadCount: 0,
      });

      setActor({ id: "operator-a", type: "operator" });
      expect(await (await fetch(`${url}/api/v2/notifications/unread-count`)).json()).toMatchObject({
        unreadCount: 1,
      });
      const operatorList = await (await fetch(`${url}/api/v2/notifications?limit=10`)).json() as any;
      expect(operatorList.items.find((item: any) => item.id === "notification:event-a-safe-stop")?.readAt)
        .toBe(NOW);
      expect(operatorList.items.find((item: any) => item.id === "notification:event-a-guided")?.readAt)
        .toBeNull();

      setActor({ id: "runtime-system", type: "system" });
      const systemCount = await fetch(`${url}/api/v2/notifications/unread-count`);
      expect(systemCount.status).toBe(200);
      expect(await systemCount.json()).toMatchObject({ unreadCount: 2 });
      const denied = await fetch(`${url}/api/v2/notifications/read-all`, {
        method: "POST",
        headers: { "Idempotency-Key": "notification-system-read-all-01" },
      });
      expect(denied.status).toBe(403);
      expect(await denied.json()).toMatchObject({
        error: { code: "notification_read_state_forbidden", category: "policy_denied" },
      });
      expect(database.prepare(`
        SELECT actor_type, actor_id, COUNT(*) AS count
        FROM notification_read_receipts
        GROUP BY actor_type, actor_id ORDER BY actor_type, actor_id
      `).all()).toEqual([
        { actor_type: "operator", actor_id: "operator-a", count: 1 },
        { actor_type: "reviewer", actor_id: "reviewer-b", count: 2 },
      ]);
      expect(() => new NotificationRepository(database).markAllRead(
        { maximumSensitivity: "private", engagementIds: ["eng-a"] },
        { id: "runtime-system", type: "system" },
        "notification-system-direct-01",
      )).toThrow("Only a human reviewer");
    } finally {
      database.close();
    }
  });

  test("rechecks mark-one visibility and binds mark-all replay to normalized authorization", async () => {
    const { database, url, setAccess } = await application();
    try {
      const oneKey = "notification-scope-replay-one-01";
      const first = await fetch(`${url}/api/v2/notifications/notification:event-a-safe-stop/read`, {
        method: "POST", headers: { "Idempotency-Key": oneKey },
      });
      expect(first.status).toBe(200);
      setAccess({ maximumSensitivity: "restricted", engagementIds: ["eng-b"] });
      const hiddenReplay = await fetch(`${url}/api/v2/notifications/notification:event-a-safe-stop/read`, {
        method: "POST", headers: { "Idempotency-Key": oneKey },
      });
      expect(hiddenReplay.status).toBe(404);

      setAccess({ maximumSensitivity: "private", engagementIds: ["eng-a"] });
      const allKey = "notification-scope-replay-all-01";
      expect((await fetch(`${url}/api/v2/notifications/read-all`, {
        method: "POST", headers: { "Idempotency-Key": allKey },
      })).status).toBe(200);
      setAccess({ maximumSensitivity: "restricted", engagementIds: ["eng-b"] });
      const changedScopeReplay = await fetch(`${url}/api/v2/notifications/read-all`, {
        method: "POST", headers: { "Idempotency-Key": allKey },
      });
      expect(changedScopeReplay.status).toBe(409);
      expect(await changedScopeReplay.json()).toMatchObject({
        error: { code: "notification_idempotency_conflict", category: "conflict" },
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM notification_read_receipts
        WHERE notification_id = 'notification:event-b-hidden'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("marks more than one thousand authorized notifications without materializing an IN bind list", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    try {
      addMission(database, {
        missionId: "mission-large", runId: "run-large", journey: "autonomous", engagementId: "eng-large",
      });
      const events = new EventRepository(database);
      for (let index = 0; index < 1_105; index += 1) {
        events.append({
          id: `event-large-${String(index).padStart(4, "0")}`,
          missionId: "mission-large",
          runId: "run-large",
          journey: "autonomous",
          eventType: "run.recovery_started",
          actorType: "system",
          summary: "Bounded recovery started",
          occurredAt: NOW,
        });
      }
      const listPlan = database.prepare(`
        EXPLAIN QUERY PLAN
        SELECT n.id
        FROM notifications n
        LEFT JOIN notification_read_receipts receipt
          ON receipt.notification_id = n.id
          AND receipt.actor_type = 'operator' AND receipt.actor_id = 'operator-large'
        JOIN events e ON e.id = substr(n.id, 14)
        JOIN missions m ON m.id = n.mission_id AND m.id = e.mission_id
        JOIN runs r ON r.id = n.run_id AND r.id = e.run_id
        WHERE e.sensitivity IN ('public', 'internal')
        ORDER BY n.created_at DESC, n.id DESC LIMIT 21
      `).all() as Array<{ detail: string }>;
      expect(listPlan.some((item) => item.detail === "SCAN e")).toBeFalse();
      expect(listPlan.some((item) => item.detail.includes("idx_notifications_created_time"))).toBeTrue();
      expect(listPlan.some((item) => item.detail.includes("TEMP B-TREE"))).toBeFalse();

      const unreadPlan = database.prepare(`
        EXPLAIN QUERY PLAN
        SELECT n.id
        FROM notifications n
        LEFT JOIN notification_read_receipts receipt
          ON receipt.notification_id = n.id
          AND receipt.actor_type = 'operator' AND receipt.actor_id = 'operator-large'
        JOIN events e ON e.id = substr(n.id, 14)
        JOIN missions m ON m.id = n.mission_id AND m.id = e.mission_id
        JOIN runs r ON r.id = n.run_id AND r.id = e.run_id
        WHERE receipt.read_at IS NULL AND e.sensitivity IN ('public', 'internal')
        ORDER BY n.created_at DESC, n.id DESC LIMIT 21
      `).all() as Array<{ detail: string }>;
      expect(unreadPlan.some((item) => item.detail.includes("idx_notifications_created_time"))).toBeTrue();
      expect(unreadPlan.some((item) => item.detail.includes("notification_read_receipts"))).toBeTrue();
      expect(unreadPlan.some((item) => item.detail.includes("TEMP B-TREE"))).toBeFalse();

      const access: OperationsAccessPolicy = { maximumSensitivity: "internal", engagementIds: ["eng-large"] };
      const actor: OperationsActor = { id: "operator-large", type: "operator" };
      const result = new NotificationRepository(database, () => new Date(NOW)).markAllRead(
        access,
        actor,
        "notification-large-mark-all-01",
      );
      expect(result.mutation.changedCount).toBe(1_105);
      expect(new NotificationRepository(database).unreadCount(access, actor).unreadCount).toBe(0);
    } finally {
      database.close();
    }
  });
});

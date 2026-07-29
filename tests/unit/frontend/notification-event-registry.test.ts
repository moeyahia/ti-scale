import { describe, expect, test } from "bun:test";
import {
  isActionableNotificationEvent,
  notificationDefinitionFor,
  NOTIFICATION_EVENT_REGISTRY,
} from "../../../src/domain/notificationEventRegistry";
import { invalidateNotificationQueries } from "../../../src/data/events/EventStreamProvider";

describe("notification event registry", () => {
  test("classifies actionable events with their exact journey boundary", () => {
    expect(Object.keys(NOTIFICATION_EVENT_REGISTRY).length).toBe(21);
    expect(isActionableNotificationEvent("run.step_advanced", "autonomous")).toBeFalse();
    expect(isActionableNotificationEvent("memory.candidate_created", "autonomous")).toBeTrue();
    expect(isActionableNotificationEvent("memory.candidate_created", "guided")).toBeTrue();
    expect(isActionableNotificationEvent("run.safe_stopped", "autonomous")).toBeTrue();
    expect(isActionableNotificationEvent("run.safe_stopped", "guided")).toBeFalse();
    expect(isActionableNotificationEvent("guided.decision_requested", "guided")).toBeTrue();
    expect(isActionableNotificationEvent("guided.decision_requested", "autonomous")).toBeFalse();
    expect(notificationDefinitionFor("run.recovery_blocked", "guided")).toMatchObject({
      notificationType: "recovery_blocked",
      severity: "critical",
      title: "Run recovery blocked",
    });
  });

  test("invalidates exactly the two notification queries only for an actionable event", () => {
    const invalidated: string[] = [];
    const cache = { invalidate: (key: string) => { invalidated.push(key); } };

    expect(invalidateNotificationQueries(cache, {
      type: "run.step_advanced",
      journey: "autonomous",
    })).toBeFalse();
    expect(invalidated).toEqual([]);

    expect(invalidateNotificationQueries(cache, {
      type: "memory.candidate_created",
      journey: "guided",
    })).toBeTrue();
    expect(invalidated).toEqual(["notifications:recent", "notifications:unread"]);

    invalidated.length = 0;
    expect(invalidateNotificationQueries(cache, {
      type: "run.safe_stopped",
      journey: "guided",
    })).toBeFalse();
    expect(invalidated).toEqual([]);
  });
});

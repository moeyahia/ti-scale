import { describe, expect, test } from "bun:test";
import { parseOperationalEvent } from "../../../src/domain/schemas/commandOs";

const wireEvent = {
  id: "evt_wire_1",
  sequence: 4,
  type: "assignment.heartbeat",
  timestamp: "2026-07-16T00:00:00.000Z",
  missionId: "mission_wire_1",
  runId: "run_wire_1",
  journey: "autonomous",
  summary: "Worker heartbeat retained",
  actor: { type: "worker", id: null },
  payload: { progress: true },
  schemaVersion: 1,
  traceId: null,
  spanId: null,
  sensitivity: "internal",
  redaction: { paths: [] },
  contextPackId: null,
} as const;

describe("operational event wire parser", () => {
  test("accepts the exact durable SSE envelope including worker actors", () => {
    expect(parseOperationalEvent(wireEvent)).toEqual(wireEvent);
  });

  test("rejects the obsolete published aliases and missing correlation fields", () => {
    const { type: _type, redaction: _redaction, ...rest } = wireEvent;
    expect(() => parseOperationalEvent({ ...rest, eventType: wireEvent.type, redacted: false }))
      .toThrow("unsupported fields");
    const { contextPackId: _contextPackId, ...withoutContextPack } = wireEvent;
    expect(() => parseOperationalEvent(withoutContextPack)).toThrow("event context pack id");
  });

  test("rejects invalid sequence, schema version, actor, and sensitivity values", () => {
    expect(() => parseOperationalEvent({ ...wireEvent, sequence: 0 })).toThrow("positive integer");
    expect(() => parseOperationalEvent({ ...wireEvent, schemaVersion: "2.4" })).toThrow("must be a number");
    expect(() => parseOperationalEvent({ ...wireEvent, actor: { type: "commander", id: "agent-1" } })).toThrow("actor type");
    expect(() => parseOperationalEvent({ ...wireEvent, sensitivity: "secret" })).toThrow("sensitivity");
  });
});

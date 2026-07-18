import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { RuntimeRepository } from "../RuntimeRepository";

const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe("RuntimeRepository fenced idempotency", () => {
  test("reserves once, blocks concurrent work, and returns the durable completed response", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const repository = new RuntimeRepository(database);
    const request = { params: { runId: "run-idempotency" }, body: { reason: "Pause once" } };

    const claimed = repository.transaction(() => repository.claimIdempotent(
      "run.pause",
      "idempotency-pause-key",
      request,
      "operator:test",
      "2026-07-16T12:00:00.000Z",
      30_000,
    ));
    expect(claimed.kind).toBe("claimed");
    if (claimed.kind !== "claimed") throw new Error("Expected the first worker to own the claim");

    expect(repository.transaction(() => repository.claimIdempotent(
      "run.pause",
      "idempotency-pause-key",
      request,
      "operator:test",
      "2026-07-16T12:00:01.000Z",
      30_000,
    ))).toEqual({ kind: "in_progress", leaseExpiresAt: "2026-07-16T12:00:30.000Z" });

    const response = { schemaVersion: "2.4", run: { id: "run-idempotency", status: "blocked" } } as const;
    expect(repository.transaction(() => repository.completeIdempotentClaim(
      "run.pause",
      "idempotency-pause-key",
      request,
      response,
      claimed.ownerToken,
      "operator:test",
      "2026-07-16T12:00:02.000Z",
    ))).toEqual(response);
    expect(repository.transaction(() => repository.claimIdempotent(
      "run.pause",
      "idempotency-pause-key",
      request,
      "operator:test",
      "2026-07-16T12:00:03.000Z",
      30_000,
    ))).toEqual({ kind: "completed", response });
    expect(() => repository.transaction(() => repository.claimIdempotent(
      "run.pause",
      "idempotency-pause-key",
      { ...request, body: { reason: "A different mutation" } },
      "operator:test",
      "2026-07-16T12:00:04.000Z",
      30_000,
    ))).toThrow("Idempotency key was reused with a different request");
  });

  test("reclaims only an expired abandoned reservation", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const repository = new RuntimeRepository(database);
    const request = { params: { runId: "run-abandoned" }, body: { reason: "Cancel once" } };
    const first = repository.transaction(() => repository.claimIdempotent(
      "run.cancel",
      "idempotency-cancel-key",
      request,
      "operator:test",
      "2026-07-16T12:00:00.000Z",
      1_000,
    ));
    const second = repository.transaction(() => repository.claimIdempotent(
      "run.cancel",
      "idempotency-cancel-key",
      request,
      "operator:test",
      "2026-07-16T12:00:01.001Z",
      1_000,
    ));
    expect(first.kind).toBe("claimed");
    expect(second.kind).toBe("claimed");
    if (first.kind === "claimed" && second.kind === "claimed") {
      expect(second.ownerToken).not.toBe(first.ownerToken);
      expect(() => repository.transaction(() => repository.completeIdempotentClaim(
        "run.cancel",
        "idempotency-cancel-key",
        request,
        { schemaVersion: "2.4", status: "cancelled-by-stale-worker" },
        first.ownerToken,
        "operator:test",
        "2026-07-16T12:00:01.002Z",
      ))).toThrow("runtime mutation claim belongs to another worker");
    }
  });

  test("heartbeats extend only the current owner and stale workers stay fenced", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const repository = new RuntimeRepository(database);
    const request = { operatorId: "operator:test", params: { runId: "run-heartbeat" }, body: { reason: "Pause" } };
    const first = repository.transaction(() => repository.claimIdempotent(
      "run.pause",
      "idempotency-heartbeat-key",
      request,
      "operator:test",
      "2026-07-16T12:00:00.000Z",
      1_000,
    ));
    if (first.kind !== "claimed") throw new Error("Expected the first heartbeat owner");
    expect(repository.transaction(() => repository.heartbeatIdempotentClaim(
      "run.pause",
      "idempotency-heartbeat-key",
      request,
      first.ownerToken,
      "operator:test",
      "2026-07-16T12:00:00.500Z",
      2_000,
    ))).toBe("2026-07-16T12:00:02.500Z");
    expect(repository.transaction(() => repository.claimIdempotent(
      "run.pause",
      "idempotency-heartbeat-key",
      request,
      "operator:test",
      "2026-07-16T12:00:01.100Z",
      1_000,
    ))).toEqual({ kind: "in_progress", leaseExpiresAt: "2026-07-16T12:00:02.500Z" });
    const reclaimed = repository.transaction(() => repository.claimIdempotent(
      "run.pause",
      "idempotency-heartbeat-key",
      request,
      "operator:test",
      "2026-07-16T12:00:02.501Z",
      1_000,
    ));
    expect(reclaimed.kind).toBe("claimed");
    expect(() => repository.transaction(() => repository.heartbeatIdempotentClaim(
      "run.pause",
      "idempotency-heartbeat-key",
      request,
      first.ownerToken,
      "operator:test",
      "2026-07-16T12:00:02.600Z",
      1_000,
    ))).toThrow("runtime mutation claim belongs to another worker");
  });
});

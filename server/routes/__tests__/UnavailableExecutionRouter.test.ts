import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createUnavailableExecutionRouter } from "../UnavailableExecutionRouter";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
});

async function application(): Promise<string> {
  const app = express();
  app.use(express.json());
  app.use(createUnavailableExecutionRouter());
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("standalone unavailable execution contract", () => {
  test.each([
    ["/api/v2/guided/mission-one/commander/show-next-step", "guided_commander_runtime_unavailable"],
    ["/api/v2/guided-decisions/decision-one/approve", "mission_runtime_mutation_unavailable"],
    ["/api/v2/runs/run-one/pause", "mission_runtime_mutation_unavailable"],
  ] as const)("returns a structured fail-closed response for %s", async (path, code) => {
    const base = await application();
    const response = await fetch(`${base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-request-id")).toBeTruthy();
    expect(await response.json()).toMatchObject({
      error: {
        code,
        retryable: false,
        category: "dependency_missing",
        humanMessage: expect.any(String),
        remediation: expect.any(String),
        traceId: expect.any(String),
      },
    });
  });
});

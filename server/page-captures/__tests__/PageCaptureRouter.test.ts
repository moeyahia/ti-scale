import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { SqliteDatabase } from "../../db";
import {
  createPageCaptureRouter,
  type PageCaptureAuthorizationRequest,
} from "../PageCaptureRouter";
import type { CreatePageCaptureInput } from "../types";
import {
  MISSION_ID,
  RUN_ID,
  createPageCaptureFixtureDatabase,
  validPageCaptureInput,
} from "./fixtures";

interface Harness {
  readonly database: SqliteDatabase;
  readonly server: Server;
  readonly origin: string;
  readonly state: {
    actor: { readonly id: string; readonly type: "operator" | "agent" } | undefined;
    allowed: boolean;
    readonly authorizations: PageCaptureAuthorizationRequest[];
  };
}

const harnesses: Harness[] = [];

async function createHarness(): Promise<Harness> {
  const database = createPageCaptureFixtureDatabase();
  const state: Harness["state"] = {
    actor: { id: "operator-page-capture", type: "operator" },
    allowed: true,
    authorizations: [],
  };
  const app = express();
  app.use(express.json());
  app.use(createPageCaptureRouter({
    database,
    resolveActor: () => state.actor,
    authorize: (_request, _actor, authorization) => {
      state.authorizations.push(authorization);
      return state.allowed;
    },
    clock: () => new Date("2026-07-16T18:00:00.000Z"),
  }));
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  const harness = { database, server, origin: `http://127.0.0.1:${address.port}`, state };
  harnesses.push(harness);
  return harness;
}

afterEach(async () => {
  await Promise.all(harnesses.splice(0).map(async (harness) => {
    await new Promise<void>((resolve) => harness.server.close(() => resolve()));
    harness.database.close();
  }));
});

async function request(
  harness: Harness,
  path: string,
  options: {
    readonly method?: string;
    readonly key?: string;
    readonly body?: unknown;
  } = {},
): Promise<{ readonly status: number; readonly headers: Headers; readonly body: Record<string, unknown> }> {
  const headers = new Headers({ "X-Request-ID": "page-capture-router-test" });
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.key) headers.set("Idempotency-Key", options.key);
  const response = await fetch(`${harness.origin}${path}`, {
    method: options.method ?? "GET",
    headers,
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
  return { status: response.status, headers: response.headers, body: await response.json() as Record<string, unknown> };
}

describe("PageCaptureRouter", () => {
  test("creates, idempotently replays, lists, and reads canonical gallery records", async () => {
    const harness = await createHarness();
    const input = validPageCaptureInput();
    const created = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`, {
      method: "POST",
      key: "page-capture-create-0001",
      body: Object.fromEntries(Object.entries(input).filter(([key]) => key !== "missionId")),
    });
    expect(created.status).toBe(201);
    expect(created.headers.get("idempotency-replayed")).toBe("false");
    expect(created.headers.get("cache-control")).toBe("no-store");
    const record = created.body.record as { readonly id: string; readonly gallery: { readonly previewAvailable: boolean } };
    expect(record.gallery.previewAvailable).toBe(true);
    expect(harness.state.authorizations.at(-1)).toEqual({
      missionId: MISSION_ID,
      runId: RUN_ID,
      capability: "manage_page_captures",
    });

    const replay = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`, {
      method: "POST",
      key: "page-capture-create-0001",
      body: Object.fromEntries(Object.entries(input).filter(([key]) => key !== "missionId")),
    });
    expect(replay.status).toBe(200);
    expect(replay.headers.get("idempotency-replayed")).toBe("true");
    expect(replay.body).toEqual(created.body);
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM page_captures").get() as { count: number }).count).toBe(1);

    const listed = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/page-captures?runId=${RUN_ID}&limit=10`,
    );
    expect(listed.status).toBe(200);
    expect((listed.body.items as unknown[])).toHaveLength(1);
    expect(harness.state.authorizations.at(-1)).toEqual({
      missionId: MISSION_ID,
      runId: RUN_ID,
      capability: "read_page_captures",
    });

    const detail = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/page-captures/${record.id}`,
    );
    expect(detail.status).toBe(200);
    expect((detail.body.record as { readonly id: string }).id).toBe(record.id);
  });

  test("fails closed for missing identity, policy denial, missing idempotency, unknown fields, and changed replay bodies", async () => {
    const harness = await createHarness();
    harness.state.actor = undefined;
    const unauthenticated = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`);
    expect(unauthenticated.status).toBe(401);
    expect((unauthenticated.body.error as { readonly code: string }).code).toBe("page_capture_authentication_required");
    expect(unauthenticated.headers.get("x-request-id")).toBe("page-capture-router-test");

    harness.state.actor = { id: "operator-page-capture", type: "operator" };
    harness.state.allowed = false;
    const denied = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`);
    expect(denied.status).toBe(403);
    expect((denied.body.error as { readonly category: string }).category).toBe("policy_denied");
    harness.state.allowed = true;

    const body = Object.fromEntries(Object.entries(validPageCaptureInput()).filter(([key]) => key !== "missionId"));
    const missingKey = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`, {
      method: "POST",
      body,
    });
    expect(missingKey.status).toBe(400);
    expect((missingKey.body.error as { readonly code: string }).code).toBe("page_capture_idempotency_key_required");

    const unknownField = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`, {
      method: "POST",
      key: "page-capture-unknown-0001",
      body: { ...body, rawHtml: "<secret>not accepted</secret>" },
    });
    expect(unknownField.status).toBe(400);
    expect((unknownField.body.error as { readonly code: string }).code).toBe("invalid_page_capture_request");

    const first = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`, {
      method: "POST",
      key: "page-capture-conflict-0001",
      body,
    });
    expect(first.status).toBe(201);
    const changed: CreatePageCaptureInput = validPageCaptureInput({ title: "Materially changed title" });
    const changedBody = Object.fromEntries(Object.entries(changed).filter(([key]) => key !== "missionId"));
    const conflict = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`, {
      method: "POST",
      key: "page-capture-conflict-0001",
      body: changedBody,
    });
    expect(conflict.status).toBe(409);
    expect((conflict.body.error as { readonly code: string }).code).toBe("run_intelligence_idempotency_conflict");
  });

  test("returns precise V2 envelopes for scope and query failures", async () => {
    const harness = await createHarness();
    const query = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures?raw=true`);
    expect(query.status).toBe(400);
    expect(query.body.error).toMatchObject({
      code: "invalid_page_capture_query",
      category: "invalid_input",
      traceId: "page-capture-router-test",
    });

    const body = Object.fromEntries(Object.entries(validPageCaptureInput({
      url: "https://portal.example.test/app/admin/secret",
    })).filter(([key]) => key !== "missionId"));
    const prohibited = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`, {
      method: "POST",
      key: "page-capture-prohibit-0001",
      body,
    });
    expect(prohibited.status).toBe(409);
    expect(prohibited.body.error).toMatchObject({
      code: "page_capture_target_prohibited",
      category: "scope_conflict",
      retryable: false,
    });
  });
});

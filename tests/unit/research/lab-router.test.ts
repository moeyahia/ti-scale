import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../../server/db";
import { createResearchLabRouter } from "../../../server/research";

const servers: Server[] = [];
const databases: SqliteDatabase[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  databases.splice(0).reverse().forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

async function fixture(): Promise<{
  readonly database: SqliteDatabase;
  readonly filename: string;
  readonly root: string;
}> {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-research-router-"));
  directories.push(directory);
  const filename = join(directory, "research.sqlite");
  const database = createDatabaseConnection({ filename, busyTimeoutMs: 25, verifyIntegrity: false });
  databases.push(database);
  migrateDatabase(database);
  const app = express();
  app.use(express.json());
  app.use(createResearchLabRouter({
    database,
    resolveActor: (request) => {
      const id = request.get("X-Test-Actor")?.trim();
      if (!id) return undefined;
      const role = request.get("X-Test-Role");
      return {
        id,
        type: role === "reviewer" || role === "admin"
          ? role
          : "operator",
      };
    },
    authorizePromotion: (_request, actor) =>
      actor.type === "reviewer" || actor.type === "admin",
  }));
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Research Lab test server has no address");
  return { database, filename, root: `http://127.0.0.1:${address.port}` };
}

async function request(
  root: string,
  path: string,
  body: unknown,
  idempotencyKey: string,
): Promise<Response> {
  return fetch(`${root}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
      "X-Test-Actor": "operator-router",
    },
    body: JSON.stringify(body),
  });
}

describe("Research Lab HTTP mutation boundary", () => {
  test("requires an authenticated, explicitly authorized reviewer for human promotion", async () => {
    const { root } = await fixture();
    const path = "/api/v2/research/experiments/not-yet-created/promotion";
    const body = {
      expectedVersion: 1,
      action: "reject",
      rationale: "Independent reviewer rejects this represented candidate.",
      evidenceRefs: ["review-evidence"],
    };
    const anonymous = await fetch(`${root}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "research-router-anonymous",
      },
      body: JSON.stringify(body),
    });
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toMatchObject({
      error: { code: "operator_identity_required" },
    });

    const operator = await request(
      root,
      path,
      body,
      "research-router-operator-forbidden",
    );
    expect(operator.status).toBe(403);
    expect(await operator.json()).toMatchObject({
      error: {
        code: "research_promotion_forbidden",
        category: "authorization_denied",
      },
    });

    const reviewer = await fetch(`${root}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "research-router-reviewer",
        "X-Test-Actor": "reviewer-router",
        "X-Test-Role": "reviewer",
      },
      body: JSON.stringify(body),
    });
    expect(reviewer.status).toBe(404);
    expect(await reviewer.json()).toMatchObject({
      error: { code: "research_promotion_not_found" },
    });

    const multiline = await fetch(`${root}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "research-router-multiline",
        "X-Test-Actor": "reviewer-router",
        "X-Test-Role": "reviewer",
      },
      body: JSON.stringify({
        ...body,
        rationale:
          "Independent review passed the represented boundary.\nEvidence remained reproducible.",
      }),
    });
    expect(multiline.status).toBe(404);

    for (const [idempotencyKey, evidenceRefs] of [
      ["research-router-duplicate-evidence", ["receipt-1", "receipt-1"]],
      ["research-router-control-evidence", ["receipt-1\u0000hidden"]],
    ] as const) {
      const invalid = await fetch(`${root}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
          "X-Test-Actor": "reviewer-router",
          "X-Test-Role": "reviewer",
        },
        body: JSON.stringify({ ...body, evidenceRefs }),
      });
      expect(invalid.status).toBe(400);
      expect(await invalid.json()).toMatchObject({
        error: { code: "invalid_research_request" },
      });
    }
  });

  test("classifies a real SQLite write reservation as retryable and replays the exact idempotent creation", async () => {
    const { database, filename, root } = await fixture();
    const locker = createDatabaseConnection({ filename, busyTimeoutMs: 0, verifyIntegrity: false });
    databases.push(locker);
    locker.exec("BEGIN IMMEDIATE");
    const body = { catalogId: "specialist_routing_quality", ownerAcknowledged: true };
    const idempotencyKey = "research-router-busy-create";
    const unavailable = await request(root, "/api/v2/research/campaigns", body, idempotencyKey);
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers.get("Retry-After")).toBe("1");
    expect(await unavailable.json()).toMatchObject({
      error: {
        code: "research_store_busy",
        humanMessage: "Another local operation is briefly updating the Research Lab.",
        retryable: true,
        category: "persistence",
        remediation: "Try this exact change again; Ti-Scale will reuse its original submission key.",
      },
    });
    const readable = await fetch(`${root}/api/v2/research`, {
      headers: { "X-Test-Actor": "operator-router" },
    });
    expect(readable.status, await readable.clone().text()).toBe(200);
    locker.exec("ROLLBACK");

    const created = await request(root, "/api/v2/research/campaigns", body, idempotencyKey);
    expect(created.status, await created.clone().text()).toBe(201);
    const payload = await created.json() as { readonly campaign: { readonly id: string } };
    const replay = await request(root, "/api/v2/research/campaigns", body, idempotencyKey);
    expect(replay.status).toBe(201);
    expect(await replay.json()).toEqual(expect.objectContaining({ campaign: expect.objectContaining({ id: payload.campaign.id }) }));
    expect(database.prepare("SELECT COUNT(*) AS count FROM research_campaigns").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE action = 'research_campaign.created'").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM research_charters").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM experiments").get()).toEqual({ count: 0 });
  });

  test("returns a non-retryable optimistic conflict, then accepts a reviewed current version with a new key", async () => {
    const { database, root } = await fixture();
    const createResponse = await request(root, "/api/v2/research/campaigns", {
      catalogId: "memory_retrieval_precision",
      ownerAcknowledged: true,
    }, "research-router-version-create");
    expect(createResponse.status, await createResponse.clone().text()).toBe(201);
    const created = await createResponse.json() as { readonly campaign: { readonly id: string; readonly updatedAt: string } };
    const concurrentUpdatedAt = "2099-07-16T14:00:01.000Z";
    database.prepare("UPDATE research_campaigns SET updated_at = ? WHERE id = ?")
      .run(concurrentUpdatedAt, created.campaign.id);

    const reason = "The canonical benchmark needs review before any experiment starts.";
    const conflict = await request(
      root,
      `/api/v2/research/campaigns/${encodeURIComponent(created.campaign.id)}/stop`,
      { expectedUpdatedAt: created.campaign.updatedAt, reason },
      "research-router-version-stale",
    );
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toMatchObject({
      error: {
        code: "research_campaign_version_conflict",
        humanMessage: "The campaign changed after this view loaded.",
        retryable: false,
        category: "conflict",
        remediation: "Refresh the Research Lab and review the current campaign state.",
      },
    });

    const snapshotResponse = await fetch(`${root}/api/v2/research`, { headers: { "X-Test-Actor": "operator-router" } });
    expect(snapshotResponse.status).toBe(200);
    const snapshot = await snapshotResponse.json() as { readonly campaigns: readonly { readonly id: string; readonly updatedAt: string }[] };
    expect(snapshot.campaigns.find(({ id }) => id === created.campaign.id)?.updatedAt).toBe(concurrentUpdatedAt);
    const stopped = await request(
      root,
      `/api/v2/research/campaigns/${encodeURIComponent(created.campaign.id)}/stop`,
      { expectedUpdatedAt: concurrentUpdatedAt, reason },
      "research-router-version-reviewed",
    );
    expect(stopped.status, await stopped.clone().text()).toBe(200);
    expect(await stopped.json()).toMatchObject({ campaign: { id: created.campaign.id, status: "stopped" } });
    expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE resource_id = ? AND action = 'research_campaign.stopped'")
      .get(created.campaign.id)).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM research_charters WHERE campaign_id = ?").get(created.campaign.id)).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM experiments WHERE campaign_id = ?").get(created.campaign.id)).toEqual({ count: 0 });
  });
});

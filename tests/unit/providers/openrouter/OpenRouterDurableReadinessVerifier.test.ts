import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BrainContextService } from "../../../../server/brain-runtime";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../../../server/db";
import { MemoryRepository, SecondBrainService } from "../../../../server/memory";
import {
  OpenRouterDurableReadinessVerifier,
  OpenRouterPlanningError,
  resolveOpenRouterModelConfiguration,
} from "../../../../server/providers/openrouter";

const SECRET = "sk-or-v1-readiness-secret-that-must-never-escape";
const databases: SqliteDatabase[] = [];
const directories: string[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function credential(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-openrouter-durable-readiness-"));
  directories.push(directory);
  chmodSync(directory, 0o700);
  const path = join(directory, "key");
  writeFileSync(path, SECRET, { mode: 0o600 });
  return path;
}

function fixture(fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const secondBrain = new SecondBrainService(new MemoryRepository(database));
  const brainContext = new BrainContextService({ database, secondBrain });
  return {
    database,
    verifier: new OpenRouterDurableReadinessVerifier({
      database,
      secondBrain,
      brainContext,
      credentialPath: credential(),
      fetch,
    }),
  };
}

function successfulResponse(): Response {
  return new Response(JSON.stringify({
    model: "openai/gpt-5.2",
    choices: [{
      finish_reason: "stop",
      message: { content: "{\"ready\":true}", tool_calls: [] },
    }],
    usage: {
      prompt_tokens: 17,
      completion_tokens: 4,
      total_tokens: 21,
      cost: 0.00042,
    },
  }), { status: 200, headers: { "content-type": "application/json" } });
}

describe("OpenRouterDurableReadinessVerifier", () => {
  test("uses a fresh empty Context Pack and one-shot request authorization for every completion", async () => {
    const calls: Array<{ readonly authorization: string | null; readonly body: string }> = [];
    const { database, verifier } = fixture(async (_input, init) => {
      calls.push({
        authorization: new Headers(init?.headers).get("authorization"),
        body: String(init?.body ?? ""),
      });
      return successfulResponse();
    });
    const configuration = resolveOpenRouterModelConfiguration({ model: "openai/gpt-5.2" });

    const first = await verifier.verify(configuration, new AbortController().signal);
    const second = await verifier.verify(configuration, new AbortController().signal);

    expect(first).toMatchObject({
      requestedModel: configuration.model,
      returnedModel: configuration.model,
      strictSchemaVerified: true,
      toolFreeVerified: true,
      exactTokenUsage: true,
      exactCostUsage: true,
      inputTokens: 17,
      outputTokens: 4,
      totalTokens: 21,
      billedCostUsd: 0.00042,
    });
    expect(second.requestAuditReceiptId).not.toBe(first.requestAuditReceiptId);
    expect(calls).toHaveLength(2);
    expect(calls.every(({ authorization }) => authorization === `Bearer ${SECRET}`)).toBe(true);
    expect(calls.every(({ body }) => body.includes("Return {\\\"ready\\\":true}."))).toBe(true);
    for (const { body } of calls) {
      const request = JSON.parse(body) as Record<string, unknown>;
      expect(request.tools).toEqual([]);
      expect(request.tool_choice).toBe("none");
      expect(request.messages).toEqual([
        {
          role: "system",
          content: "Return the constant readiness acknowledgement. This probe contains no mission data and cannot execute tools.",
        },
        { role: "user", content: "Return {\"ready\":true}." },
      ]);
    }

    expect(database.prepare(`
      SELECT status, returned_model, input_tokens, output_tokens, total_tokens,
        billed_cost_usd, exact_token_usage, exact_cost_usage, release_data_class
      FROM provider_turns ORDER BY started_at, id
    `).all()).toEqual([
      {
        status: "completed",
        returned_model: configuration.model,
        input_tokens: 17,
        output_tokens: 4,
        total_tokens: 21,
        billed_cost_usd: 0.00042,
        exact_token_usage: 1,
        exact_cost_usage: 1,
        release_data_class: "startup_readiness",
      },
      {
        status: "completed",
        returned_model: configuration.model,
        input_tokens: 17,
        output_tokens: 4,
        total_tokens: 21,
        billed_cost_usd: 0.00042,
        exact_token_usage: 1,
        exact_cost_usage: 1,
        release_data_class: "startup_readiness",
      },
    ]);
    const receipts = database.prepare(`
      SELECT context_pack_id, request_body_hash, request_authorized_at,
        selected_context_ids_json, blocked, release_data_class
      FROM provider_exposure_receipts ORDER BY created_at, id
    `).all() as Array<Record<string, unknown>>;
    expect(receipts).toHaveLength(2);
    expect(new Set(receipts.map(({ context_pack_id }) => context_pack_id)).size).toBe(2);
    expect(receipts.every((receipt) =>
      typeof receipt.request_body_hash === "string"
      && /^[a-f0-9]{64}$/u.test(receipt.request_body_hash)
      && typeof receipt.request_authorized_at === "string"
      && receipt.selected_context_ids_json === "[]"
      && receipt.blocked === 0
      && receipt.release_data_class === "startup_readiness")).toBe(true);
    expect(database.prepare(`
      SELECT DISTINCT release_data_class FROM memory_context_packs
    `).all()).toEqual([{ release_data_class: "startup_readiness" }]);
    expect(JSON.stringify({ first, second, receipts })).not.toContain(SECRET);
  });

  test("fails the canonical provider turn safely when the provider rejects the completion", async () => {
    const { database, verifier } = fixture(async () => new Response(
      JSON.stringify({ error: SECRET }),
      { status: 401, headers: { "content-type": "application/json" } },
    ));
    const configuration = resolveOpenRouterModelConfiguration({ model: "openai/gpt-5.2" });

    let failure: unknown;
    try {
      await verifier.verify(configuration, new AbortController().signal);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(OpenRouterPlanningError);
    expect(failure).toMatchObject({
      code: "openrouter_authentication_failed",
      category: "authentication_failed",
    });
    expect(database.prepare(`
      SELECT status, error_category, ended_at IS NOT NULL AS ended
      FROM provider_turns
    `).get()).toEqual({
      status: "failed",
      error_category: "authentication_failed",
      ended: 1,
    });
    expect(JSON.stringify(failure)).not.toContain(SECRET);
  });

  test("does not create an audit turn when already cancelled", async () => {
    const { database, verifier } = fixture(async () => {
      throw new Error("fetch must not run");
    });
    const controller = new AbortController();
    controller.abort();
    await expect(verifier.verify(
      resolveOpenRouterModelConfiguration({ model: "openai/gpt-5.2" }),
      controller.signal,
    )).rejects.toMatchObject({ category: "cancelled" });
    expect(database.prepare("SELECT COUNT(*) AS count FROM provider_turns").get())
      .toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs").get())
      .toEqual({ count: 0 });
  });
});

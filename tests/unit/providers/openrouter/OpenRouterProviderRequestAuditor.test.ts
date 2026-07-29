import { afterEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../../../server/db";
import {
  OpenRouterPlanningError,
  OpenRouterProviderRequestAuditor,
  resolveOpenRouterModelConfiguration,
  type ProviderRequestAuthorizationInput,
} from "../../../../server/providers/openrouter";

const databases: SqliteDatabase[] = [];
const NOW = "2026-07-18T12:00:00.000Z";
const CONFIGURATION = resolveOpenRouterModelConfiguration({ model: "openai/gpt-5.4-mini" });

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function database(): SqliteDatabase {
  const value = createDatabaseConnection({ filename: ":memory:" });
  databases.push(value);
  migrateDatabase(value);
  value.prepare(`
    INSERT INTO memory_context_packs (
      id, journey, purpose, scope_policy_json, context_budget,
      retrieval_metrics_json, created_by, created_at
    ) VALUES ('context-pack-audit', 'guided', 'Guided explanation', '{}', 1000, '{}', 'system', ?)
  `).run(NOW);
  value.prepare(`
    INSERT INTO provider_turns (
      id, provider, model, model_configuration_hash, status, started_at
    ) VALUES ('provider-turn-audit', 'openrouter', ?, ?, 'started', ?)
  `).run(CONFIGURATION.model, CONFIGURATION.configurationHash, NOW);
  value.prepare(`
    INSERT INTO provider_exposure_receipts (
      id, provider_id, model_id, provider_turn_id, context_pack_id,
      model_configuration_hash, disclosure_policy_version, input_classification,
      selected_context_ids_json, rejected_context_ids_json,
      sanitization_actions_json, exposed_payload_hash, blocked, created_at
    ) VALUES (
      'exposure-audit', 'openrouter', ?, 'provider-turn-audit', 'context-pack-audit',
      ?, 'brain-provider-context-v1', 'public', '[]', '[]', '[]', ?, 0, ?
    )
  `).run(CONFIGURATION.model, CONFIGURATION.configurationHash, "a".repeat(64), NOW);
  return value;
}

function request(overrides: Partial<ProviderRequestAuthorizationInput> = {}): ProviderRequestAuthorizationInput {
  return {
    providerId: "openrouter",
    exposure: {
      exposureReceiptId: "exposure-audit",
      contextPackId: "context-pack-audit",
      modelConfigurationHash: CONFIGURATION.configurationHash,
    },
    requestedModel: CONFIGURATION.model,
    endpoint: CONFIGURATION.endpoint,
    requestContractVersion: "ti-scale.openrouter-structured-request.v1",
    requestBodyHash: "b".repeat(64),
    requestBodyBytes: 321,
    ...overrides,
  };
}

async function failure(promise: Promise<unknown>): Promise<OpenRouterPlanningError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(OpenRouterPlanningError);
    return error as OpenRouterPlanningError;
  }
  throw new Error("Expected request audit failure");
}

describe("OpenRouterProviderRequestAuditor", () => {
  test("transactionally binds the exact body hash to the started turn and Brain receipt", async () => {
    const db = database();
    const auditor = new OpenRouterProviderRequestAuditor({
      database: db,
      now: () => new Date(NOW),
    });
    expect(await auditor.authorize(request())).toEqual({
      authorized: true,
      exposureReceiptId: "exposure-audit",
      contextPackId: "context-pack-audit",
      providerTurnId: "provider-turn-audit",
      requestedModel: CONFIGURATION.model,
      modelConfigurationHash: CONFIGURATION.configurationHash,
      requestBodyHash: "b".repeat(64),
      committedAt: NOW,
    });
    expect(db.prepare(`
      SELECT request_body_hash, request_body_bytes, request_contract_version,
        request_endpoint, request_authorized_at
      FROM provider_exposure_receipts WHERE id = 'exposure-audit'
    `).get()).toEqual({
      request_body_hash: "b".repeat(64),
      request_body_bytes: 321,
      request_contract_version: "ti-scale.openrouter-structured-request.v1",
      request_endpoint: CONFIGURATION.endpoint,
      request_authorized_at: NOW,
    });
    expect((await failure(auditor.authorize(request()))).code)
      .toBe("openrouter_request_receipt_already_authorized");
    expect((await failure(auditor.authorize(request({ requestBodyHash: "c".repeat(64) })))).code)
      .toBe("openrouter_request_hash_mismatch");
  });

  test("fails closed for blocked, stale, stopped, context, model, or configuration mismatches", async () => {
    const mutations: ReadonlyArray<readonly [string, ProviderRequestAuthorizationInput, string]> = [
      ["UPDATE provider_exposure_receipts SET blocked = 1 WHERE id = 'exposure-audit'", request(), "openrouter_request_receipt_blocked"],
      ["UPDATE provider_exposure_receipts SET created_at = '2026-07-18T11:00:00.000Z' WHERE id = 'exposure-audit'", request(), "openrouter_request_receipt_stale"],
      ["UPDATE provider_turns SET status = 'failed' WHERE id = 'provider-turn-audit'", request(), "openrouter_request_receipt_mismatch"],
      ["SELECT 1", request({ exposure: { ...request().exposure, contextPackId: "other-pack" } }), "openrouter_request_receipt_mismatch"],
      ["SELECT 1", request({ requestedModel: "openai/gpt-5.2" }), "openrouter_request_receipt_mismatch"],
      ["SELECT 1", request({ exposure: { ...request().exposure, modelConfigurationHash: "0".repeat(64) } }), "openrouter_request_receipt_mismatch"],
    ];
    for (const [sql, input, code] of mutations) {
      const db = database();
      db.exec(sql);
      const auditor = new OpenRouterProviderRequestAuditor({
        database: db,
        now: () => new Date(NOW),
      });
      expect((await failure(auditor.authorize(input))).code).toBe(code);
    }
  });

  test("reports a redacted persistence failure and leaves no partial authorization", async () => {
    const db = database();
    db.exec(`
      CREATE TRIGGER fail_provider_request_authorization
      BEFORE UPDATE OF request_body_hash ON provider_exposure_receipts
      BEGIN
        SELECT RAISE(ABORT, 'database secret should never escape');
      END;
    `);
    const auditor = new OpenRouterProviderRequestAuditor({
      database: db,
      now: () => new Date(NOW),
    });
    const error = await failure(auditor.authorize(request()));
    expect(error).toMatchObject({
      code: "openrouter_request_audit_persistence_failed",
      category: "persistence",
    });
    expect(JSON.stringify(error)).not.toContain("database secret");
    expect(db.prepare(`
      SELECT request_body_hash, request_authorized_at
      FROM provider_exposure_receipts WHERE id = 'exposure-audit'
    `).get()).toEqual({ request_body_hash: null, request_authorized_at: null });
  });
});

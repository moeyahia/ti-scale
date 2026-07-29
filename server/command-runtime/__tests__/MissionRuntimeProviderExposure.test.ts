import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  canonicalMissionMemoryNodeId,
  canonicalRunMemoryNodeId,
} from "../../brain-runtime";
import { MemoryRepository } from "../../memory";
import type { DurableAction } from "../../orchestration";
import {
  OpenRouterPlanningClient,
  OpenRouterProviderRequestAuditor,
  resolveOpenRouterModelConfiguration,
} from "../../providers/openrouter";
import {
  CommandRuntimeError,
  createMissionRuntime,
  type MissionPlanDraft,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
} from "..";

const NOW = "2026-07-18T09:00:00.000Z";
const MODEL_CONFIGURATION_HASH = "a".repeat(64);
const databases: SqliteDatabase[] = [];
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

class NoopExecution implements ResultAwareExecutionPort {
  async dispatch(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async cancelRun(_runId: string, _reason: string): Promise<void> {}
}

function database(): SqliteDatabase {
  const value = createDatabaseConnection({ filename: ":memory:" });
  databases.push(value);
  migrateDatabase(value);
  return value;
}

function credentialFile(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-mission-provider-"));
  temporaryDirectories.push(directory);
  chmodSync(directory, 0o700);
  const path = join(directory, "openrouter.key");
  writeFileSync(path, `sk-or-v1-${"x".repeat(48)}`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

const strategyResponse = {
  name: "mission_strategy",
  schema: {
    type: "object",
    properties: { strategy: { type: "string" } },
    required: ["strategy"],
    additionalProperties: false,
  },
  validate(value: unknown): { readonly strategy: string } {
    if (
      !value || typeof value !== "object" || Array.isArray(value) ||
      typeof (value as { strategy?: unknown }).strategy !== "string"
    ) throw new TypeError("Provider strategy is invalid");
    return { strategy: (value as { strategy: string }).strategy };
  },
} as const;

function seed(db: SqliteDatabase, suffix: string): {
  readonly missionId: string;
  readonly runId: string;
  readonly agentId: string;
} {
  const missionId = `mission-provider-exposure-${suffix}`;
  const runId = `run-provider-exposure-${suffix}`;
  const agentId = `agent-provider-exposure-${suffix}`;
  const memoryIds = [
    `memory-provider-approved-${suffix}`,
    `memory-provider-private-${suffix}`,
  ];
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Provider exposure fixture', 'Inspect the authorized lab service',
      'guided', 'active', 'verified', ?, 'operator:test', ?, ?, 'ti_scale')
  `).run(
    missionId,
    JSON.stringify({
      exactContextNodeIds: memoryIds,
      allowedScopes: ["verified_lessons"],
    }),
    NOW,
    NOW,
  );
  db.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES (?, ?, 'lab.internal', 'domain', 'allowed', 'lab.internal', ?)
  `).run(`target-provider-exposure-${suffix}`, missionId, NOW);
  db.prepare(`
    INSERT INTO agents (id, role, display_name, status, version, created_at, updated_at)
    VALUES (?, 'recon-specialist', 'Recon specialist', 'available', 'test-1', ?, ?)
  `).run(agentId, NOW, NOW);
  db.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, retry_count, replan_count,
      started_at, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'guided', 'planning', 0, 'Build one represented Guided step',
      ?, '{}', 0, 0, ?, ?, ?, 1, 'ti_scale')
  `).run(
    runId,
    missionId,
    JSON.stringify({
      wallClockMs: 60_000,
      providerTurns: 4,
      providerTokens: 1_000,
      estimatedCost: 1,
      retries: 2,
      replans: 1,
      concurrency: 1,
    }),
    NOW,
    NOW,
    NOW,
  );

  const memory = new MemoryRepository(db, { clock: () => new Date(NOW) });
  memory.createNode({
    id: memoryIds[0]!,
    nodeType: "lesson",
    title: "Contact ops@customer.example before the verified service check",
    summary: "Prior evidence referenced https://customer.example/admin at 10.20.30.40.",
    body: "RAW_APPROVED_MEMORY_BODY_MUST_NOT_CROSS_PROVIDER_BOUNDARY",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.95,
    lifecycleStatus: "verified",
    confirmationState: "not_required",
    provenance: {
      method: "operator_statement",
      explanation: "Local provider exposure fixture",
      sources: [{ sourceType: "message", sourceId: `source-approved-${suffix}`, acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "operator:test",
    retentionPolicy: {
      allowAutonomous: true,
      allowGuided: true,
      publicProviderDisclosure: "sanitized",
    },
  });
  memory.createNode({
    id: memoryIds[1]!,
    nodeType: "lesson",
    title: "Private local recovery detail",
    summary: "PRIVATE_MEMORY_SUMMARY_MUST_NOT_CROSS_PROVIDER_BOUNDARY",
    body: "PRIVATE_MEMORY_BODY_MUST_NOT_CROSS_PROVIDER_BOUNDARY",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.9,
    lifecycleStatus: "verified",
    confirmationState: "not_required",
    provenance: {
      method: "operator_statement",
      explanation: "Local private provider exposure fixture",
      sources: [{ sourceType: "message", sourceId: `source-private-${suffix}`, acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "operator:test",
    retentionPolicy: {
      allowAutonomous: true,
      allowGuided: true,
    },
  });
  return { missionId, runId, agentId };
}

function plan(agentId: string): MissionPlanDraft {
  return {
    strategySummary: "Collect one bounded service observation",
    rationaleSummary: "One reversible observation reduces uncertainty before deeper work",
    steps: [{
      phase: "Reconnaissance",
      title: "Inspect the approved service",
      objective: "Confirm whether the approved service responds",
      explanation: "The specialist performs one represented read-only service check.",
      rationale: "The result determines whether deeper authorized analysis is useful.",
      successCriteria: ["A bounded service response is recorded"],
      dependencyOrdinals: [],
      assignedAgentId: agentId,
      riskClass: "low",
      reversibility: "Read-only and immediately reversible",
      action: {
        actionType: "service_probe",
        actionClass: "port_service_enumeration",
        target: "lab.internal",
        arguments: { target: "lab.internal", port: 443 },
        intentSummary: "Inspect the approved HTTPS service once",
        kind: "tool",
        idempotent: true,
        destructive: false,
      },
    }],
  };
}

function runtime(db: SqliteDatabase, planner: MissionPlannerPort) {
  return createMissionRuntime({
    database: db,
    planner,
    outcomeEvaluator: {
      async evaluate() { throw new Error("Provider exposure planning fixture must not evaluate"); },
    },
    execution: new NoopExecution(),
    workerId: "provider-exposure-runtime",
    leaseTtlMs: 2_000,
    now: () => new Date(NOW),
  });
}

describe("MissionRuntimeEngine public planning provider boundary", () => {
  test("persists the receipt before the call and sends only sanitized Brain context", async () => {
    const db = database();
    const fixture = seed(db, "success");
    let called = false;
    let observed: {
      readonly turn: { readonly id: string; readonly status: string };
      readonly receipt: {
        readonly id: string;
        readonly provider_turn_id: string;
        readonly provider_id: string;
        readonly model_id: string;
        readonly model_configuration_hash: string;
        readonly selected_context_ids_json: string;
        readonly rejected_context_ids_json: string;
      };
      readonly exposureReceiptId?: string;
      readonly exposed: string;
    } | undefined;
    const planner: MissionPlannerPort = {
      providerBoundary: {
        kind: "public_provider",
        providerId: "openrouter",
        modelId: "openai/gpt-5.4",
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      },
      async plan(input) {
        called = true;
        const turn = db.prepare(`
          SELECT id, status FROM provider_turns WHERE run_id = ?
        `).get(fixture.runId) as { id: string; status: string };
        const receipt = db.prepare(`
          SELECT id, provider_turn_id, provider_id, model_id, model_configuration_hash,
            selected_context_ids_json, rejected_context_ids_json
          FROM provider_exposure_receipts WHERE provider_turn_id = ?
        `).get(turn.id) as {
          id: string;
          provider_turn_id: string;
          provider_id: string;
          model_id: string;
          model_configuration_hash: string;
          selected_context_ids_json: string;
          rejected_context_ids_json: string;
        };
        observed = {
          turn,
          receipt,
          exposureReceiptId: input.brainContext.exposureReceiptId,
          exposed: JSON.stringify(input.brainContext),
        };
        return {
          plan: plan(fixture.agentId),
          usage: {
            providerId: "openrouter",
            requestedModel: "openai/gpt-5.4",
            returnedModel: "openai/gpt-5.4-20260701",
            inputTokens: 21,
            outputTokens: 8,
            totalTokens: 29,
            providerTokens: 29,
            billedCostUsd: 0.0025,
            estimatedCost: 0.0025,
            exactTokenUsage: true,
            exactCostUsage: true,
            latencyMs: 17,
          },
        };
      },
    };
    const engine = runtime(db, planner);
    try {
      await engine.processRunNow(fixture.runId);
      expect(called).toBe(true);
      expect(observed!.turn.status).toBe("started");
      expect(observed!.receipt).toMatchObject({
        id: observed!.exposureReceiptId,
        provider_turn_id: observed!.turn.id,
        provider_id: "openrouter",
        model_id: "openai/gpt-5.4",
        model_configuration_hash: MODEL_CONFIGURATION_HASH,
      });
      expect(JSON.parse(observed!.receipt.selected_context_ids_json)).toEqual([
        "memory-provider-approved-success",
      ]);
      expect(JSON.parse(observed!.receipt.rejected_context_ids_json)).toEqual([
        canonicalMissionMemoryNodeId(fixture.missionId),
        canonicalRunMemoryNodeId(fixture.runId),
      ]);
      expect(observed!.exposed).not.toContain("RAW_APPROVED_MEMORY_BODY");
      expect(observed!.exposed).not.toContain("PRIVATE_MEMORY_SUMMARY");
      expect(observed!.exposed).not.toContain("PRIVATE_MEMORY_BODY");
      expect(observed!.exposed).not.toContain("ops@customer.example");
      expect(observed!.exposed).not.toContain("customer.example");
      expect(observed!.exposed).not.toContain("10.20.30.40");
      expect(observed!.exposed).toContain("[REDACTED_EMAIL]");
      expect(observed!.exposed).toContain("[REDACTED_HOST]");
      expect(observed!.exposed).toContain("[REDACTED_IP]");
      const turn = db.prepare(`
        SELECT id, status, provider, model, model_configuration_hash,
          returned_model, input_tokens, output_tokens, total_tokens,
          billed_cost_usd, estimated_cost, exact_token_usage, exact_cost_usage,
          latency_ms, error_category, ended_at
        FROM provider_turns WHERE run_id = ?
      `).get(fixture.runId) as Record<string, unknown>;
      expect(turn).toMatchObject({
        status: "completed",
        provider: "openrouter",
        model: "openai/gpt-5.4",
        model_configuration_hash: MODEL_CONFIGURATION_HASH,
        returned_model: "openai/gpt-5.4-20260701",
        input_tokens: 21,
        output_tokens: 8,
        total_tokens: 29,
        billed_cost_usd: 0.0025,
        estimated_cost: 0.0025,
        exact_token_usage: 1,
        exact_cost_usage: 1,
        latency_ms: 17,
        error_category: null,
        ended_at: NOW,
      });
      expect(db.prepare(`
        SELECT COUNT(*) AS count FROM provider_exposure_receipts WHERE provider_turn_id = ?
      `).get(turn.id)).toEqual({ count: 1 });
      const run = db.prepare("SELECT status, budget_usage_json FROM runs WHERE id = ?")
        .get(fixture.runId) as { status: string; budget_usage_json: string };
      expect(run.status).toBe("waiting_guided_decision");
      expect(JSON.parse(run.budget_usage_json)).toMatchObject({
        providerTurns: 1,
        providerTokens: 29,
        estimatedCost: 0.0025,
      });
    } finally {
      await engine.stop();
    }
  });

  test("binds MissionRuntimeEngine planning through the real OpenRouter request auditor and persists exact returned usage", async () => {
    const db = database();
    const fixture = seed(db, "audited-exact");
    const configuration = resolveOpenRouterModelConfiguration({ model: "openai/gpt-5.4" });
    let outboundBody = "";
    let auditWasDurableBeforeFetch = false;
    const client = new OpenRouterPlanningClient({
      credentialPath: credentialFile(),
      requestAuditor: new OpenRouterProviderRequestAuditor({ database: db }),
      fetch: async (_input, init) => {
        if (typeof init?.body !== "string") throw new TypeError("Expected one canonical string body");
        outboundBody = init.body;
        const receipt = db.prepare(`
          SELECT request_body_hash, request_body_bytes, request_authorized_at
          FROM provider_exposure_receipts
          WHERE run_id = ?
        `).get(fixture.runId) as {
          request_body_hash: string | null;
          request_body_bytes: number | null;
          request_authorized_at: string | null;
        };
        auditWasDurableBeforeFetch = receipt.request_body_hash === createHash("sha256")
          .update(outboundBody, "utf8")
          .digest("hex")
          && receipt.request_body_bytes === Buffer.byteLength(outboundBody, "utf8")
          && receipt.request_authorized_at !== null;
        const request = JSON.parse(outboundBody) as Record<string, unknown>;
        expect(request).toMatchObject({
          model: configuration.model,
          stream: false,
          tools: [],
          tool_choice: "none",
          usage: { include: true },
        });
        return new Response(JSON.stringify({
          model: "openai/gpt-5.4-20260701",
          choices: [{
            finish_reason: "stop",
            message: { content: JSON.stringify({ strategy: "Use one audited service observation" }) },
          }],
          usage: {
            prompt_tokens: 34,
            completion_tokens: 11,
            total_tokens: 45,
            cost: 0.0042,
          },
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    const planner: MissionPlannerPort = {
      providerBoundary: {
        kind: "public_provider",
        providerId: "openrouter",
        modelId: configuration.model,
        modelConfigurationHash: configuration.configurationHash,
      },
      async plan(input, signal) {
        if (!input.brainContext.exposureReceiptId) throw new TypeError("Exposure receipt is missing");
        const result = await client.callStructuredJson({
          model: configuration.model,
          messages: [
            { role: "system", content: "Return one bounded mission-planning strategy as JSON." },
            { role: "user", content: JSON.stringify(input.brainContext) },
          ],
          response: strategyResponse,
          exposure: {
            exposureReceiptId: input.brainContext.exposureReceiptId,
            contextPackId: input.brainContext.contextPackId,
            modelConfigurationHash: configuration.configurationHash,
          },
          signal,
        });
        return {
          plan: {
            ...plan(fixture.agentId),
            strategySummary: result.value.strategy,
          },
          usage: {
            providerId: result.providerId,
            requestedModel: result.requestedModel,
            returnedModel: result.returnedModel,
            inputTokens: result.usage.inputTokens,
            outputTokens: result.usage.outputTokens,
            totalTokens: result.usage.providerTokens,
            billedCostUsd: result.usage.billedCostUsd,
            exactTokenUsage: result.usage.exactTokenUsage,
            exactCostUsage: result.usage.exactCostUsage,
            latencyMs: 23,
          },
        };
      },
    };
    const engine = runtime(db, planner);
    try {
      await engine.processRunNow(fixture.runId);
      expect(auditWasDurableBeforeFetch).toBe(true);
      expect(outboundBody).not.toBe("");
      const turn = db.prepare(`
        SELECT provider, model, returned_model, model_configuration_hash, status,
          input_tokens, output_tokens, total_tokens, billed_cost_usd,
          exact_token_usage, exact_cost_usage, latency_ms
        FROM provider_turns WHERE run_id = ?
      `).get(fixture.runId) as Record<string, unknown>;
      expect(turn).toEqual({
        provider: "openrouter",
        model: configuration.model,
        returned_model: "openai/gpt-5.4-20260701",
        model_configuration_hash: configuration.configurationHash,
        status: "completed",
        input_tokens: 34,
        output_tokens: 11,
        total_tokens: 45,
        billed_cost_usd: 0.0042,
        exact_token_usage: 1,
        exact_cost_usage: 1,
        latency_ms: 23,
      });
      const receipt = db.prepare(`
        SELECT context_pack_id, model_configuration_hash, request_body_hash,
          request_body_bytes, request_contract_version, request_endpoint,
          request_authorized_at
        FROM provider_exposure_receipts WHERE run_id = ?
      `).get(fixture.runId) as Record<string, unknown>;
      expect(receipt).toMatchObject({
        model_configuration_hash: configuration.configurationHash,
        request_body_hash: createHash("sha256").update(outboundBody, "utf8").digest("hex"),
        request_body_bytes: Buffer.byteLength(outboundBody, "utf8"),
        request_contract_version: "ti-scale.openrouter-structured-request.v1",
        request_endpoint: configuration.endpoint,
      });
      expect(receipt.context_pack_id).toBeTruthy();
      expect(receipt.request_authorized_at).toBeTruthy();
      const run = db.prepare("SELECT budget_usage_json FROM runs WHERE id = ?")
        .get(fixture.runId) as { budget_usage_json: string };
      expect(JSON.parse(run.budget_usage_json)).toMatchObject({
        providerTurns: 1,
        providerTokens: 45,
        estimatedCost: 0.0042,
      });
    } finally {
      await engine.stop();
    }
  });

  test("fails closed before credential access and fetch when the runtime model-configuration hash drifts", async () => {
    const db = database();
    const fixture = seed(db, "audited-hash-drift");
    const configuration = resolveOpenRouterModelConfiguration({ model: "openai/gpt-5.4" });
    const driftedHash = configuration.configurationHash === "b".repeat(64)
      ? "c".repeat(64)
      : "b".repeat(64);
    let fetchCalled = false;
    let providerFailure: unknown;
    const client = new OpenRouterPlanningClient({
      credentialPath: join(tmpdir(), "ti-scale-credential-must-not-be-read"),
      requestAuditor: new OpenRouterProviderRequestAuditor({ database: db }),
      fetch: async () => {
        fetchCalled = true;
        throw new Error("Fetch must not run for a drifted model configuration");
      },
    });
    const planner: MissionPlannerPort = {
      providerBoundary: {
        kind: "public_provider",
        providerId: "openrouter",
        modelId: configuration.model,
        modelConfigurationHash: driftedHash,
      },
      async plan(input, signal) {
        if (!input.brainContext.exposureReceiptId) throw new TypeError("Exposure receipt is missing");
        try {
          await client.callStructuredJson({
            model: configuration.model,
            messages: [{ role: "user", content: "Return one bounded strategy." }],
            response: strategyResponse,
            exposure: {
              exposureReceiptId: input.brainContext.exposureReceiptId,
              contextPackId: input.brainContext.contextPackId,
              // The request uses the actual resolved configuration. The
              // runtime turn and Brain receipt were pinned to driftedHash.
              modelConfigurationHash: configuration.configurationHash,
            },
            signal,
          });
        } catch (error) {
          providerFailure = error;
          throw error;
        }
        throw new Error("Drifted model configuration unexpectedly passed auditing");
      },
    };
    const engine = runtime(db, planner);
    try {
      await expect(engine.processRunNow(fixture.runId)).rejects.toBeInstanceOf(CommandRuntimeError);
      expect(providerFailure).toMatchObject({
        code: "openrouter_request_receipt_mismatch",
        category: "policy_denied",
        retryable: false,
      });
      expect(fetchCalled).toBe(false);
      expect(db.prepare(`
        SELECT status, model_configuration_hash, error_category
        FROM provider_turns WHERE run_id = ?
      `).get(fixture.runId)).toEqual({
        status: "failed",
        model_configuration_hash: driftedHash,
        error_category: "policy_denied",
      });
      expect(db.prepare(`
        SELECT model_configuration_hash, request_body_hash, request_authorized_at
        FROM provider_exposure_receipts WHERE run_id = ?
      `).get(fixture.runId)).toEqual({
        model_configuration_hash: driftedHash,
        request_body_hash: null,
        request_authorized_at: null,
      });
      expect(db.prepare("SELECT status FROM runs WHERE id = ?").get(fixture.runId))
        .toEqual({ status: "blocked" });
    } finally {
      await engine.stop();
    }
  });

  test("closes a failed public-provider turn while preserving its exposure receipt", async () => {
    const db = database();
    const fixture = seed(db, "failure");
    let called = false;
    const planner: MissionPlannerPort = {
      providerBoundary: {
        kind: "public_provider",
        providerId: "openrouter",
        modelId: "openai/gpt-5.4",
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      },
      async plan(input) {
        called = true;
        expect(input.brainContext.exposureReceiptId).toBeTruthy();
        expect(db.prepare(`
          SELECT COUNT(*) AS count FROM provider_exposure_receipts
          WHERE id = ? AND provider_turn_id IN (
            SELECT id FROM provider_turns WHERE run_id = ? AND status = 'started'
          )
        `).get(input.brainContext.exposureReceiptId!, fixture.runId)).toEqual({ count: 1 });
        throw new CommandRuntimeError(502, "planning_provider_unavailable", "Planning provider unavailable", {
          humanMessage: "The planning provider is temporarily unavailable.",
          retryable: false,
          category: "provider_unavailable",
        });
      },
    };
    const engine = runtime(db, planner);
    try {
      await expect(engine.processRunNow(fixture.runId)).rejects.toMatchObject({
        code: "planning_provider_unavailable",
      });
      expect(called).toBe(true);
      const turn = db.prepare(`
        SELECT id, status, input_tokens, output_tokens, estimated_cost,
          latency_ms, error_category, ended_at
        FROM provider_turns WHERE run_id = ?
      `).get(fixture.runId) as Record<string, unknown>;
      expect(turn).toMatchObject({
        status: "failed",
        input_tokens: null,
        output_tokens: null,
        estimated_cost: null,
        error_category: "provider_unavailable",
        ended_at: NOW,
      });
      expect(turn.latency_ms).toBeGreaterThanOrEqual(0);
      expect(db.prepare(`
        SELECT COUNT(*) AS count FROM provider_exposure_receipts WHERE provider_turn_id = ?
      `).get(turn.id)).toEqual({ count: 1 });
      expect(db.prepare("SELECT status FROM runs WHERE id = ?").get(fixture.runId))
        .toEqual({ status: "blocked" });
    } finally {
      await engine.stop();
    }
  });

  test("does not create provider audit records for an undeclared local planner", async () => {
    const db = database();
    const fixture = seed(db, "local");
    db.prepare("UPDATE runs SET budget_json = ? WHERE id = ?").run(JSON.stringify({
      wallClockMs: 60_000,
      providerTurns: 4,
      retries: 2,
      replans: 1,
      concurrency: 1,
    }), fixture.runId);
    const engine = runtime(db, {
      async plan(input) {
        expect(input.brainContext.exposureReceiptId).toBeUndefined();
        return plan(fixture.agentId);
      },
    });
    try {
      await engine.processRunNow(fixture.runId);
      expect(db.prepare("SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?")
        .get(fixture.runId)).toEqual({ count: 0 });
      expect(db.prepare("SELECT COUNT(*) AS count FROM provider_exposure_receipts WHERE run_id = ?")
        .get(fixture.runId)).toEqual({ count: 0 });
    } finally {
      await engine.stop();
    }
  });
});

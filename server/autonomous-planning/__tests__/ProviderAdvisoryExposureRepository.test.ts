import { afterEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  OpenRouterProviderRequestAuditor,
} from "../../providers/openrouter";
import {
  providerAdvisoryDisclosureIdentityHash,
  ProviderAdvisoryExposureRepository,
  ProviderAdvisoryPlanningError,
  ProviderAdvisoryRequestBindingRepository,
  buildProviderAdvisoryCandidateCatalog,
  prepareProviderAdvisoryBrief,
} from "../index";

const NOW = "2026-07-28T18:00:00.000Z";
const MISSION_ID = "mission-provider-advisory-exposure";
const RUN_ID = "run-provider-advisory-exposure";
const CONTEXT_PACK_ID = "context-provider-advisory-exposure";
const PROVIDER_TURN_ID = "provider-turn-advisory-exposure";
const PLANNING_REQUEST_ID = "planning-request-advisory-exposure";
const MODEL = "openai/gpt-5.2";
const MODEL_CONFIGURATION_HASH = "c".repeat(64);
const TARGET = "10.129.46.243";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function database(): SqliteDatabase {
  const result = createDatabaseConnection({ filename: ":memory:" });
  databases.push(result);
  migrateDatabase(result);
  return result;
}

function seed(db: SqliteDatabase): void {
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Advisory exposure fixture',
      'Inspect one exact authorized lab host', 'autonomous', 'active',
      'verified', '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(MISSION_ID, NOW, NOW);
  db.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, retry_count, replan_count,
      started_at, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'autonomous', 'planning', 0,
      'Build a contract-bound advisory plan', ?, '{}', 0, 0,
      ?, ?, ?, 1, 'ti_scale')
  `).run(
    RUN_ID,
    MISSION_ID,
    JSON.stringify({
      wallClockMs: 60_000,
      providerTurns: 2,
      providerTokens: 4_000,
      estimatedCost: 2,
      retries: 1,
      replans: 1,
      concurrency: 1,
    }),
    NOW,
    NOW,
    NOW,
  );
  db.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json,
      created_by, created_at
    ) VALUES (?, ?, ?, 'autonomous', 'Autonomous planning',
      'bounded advisory planning', '{}', 8, '{}', 'mission-planner', ?)
  `).run(CONTEXT_PACK_ID, MISSION_ID, RUN_ID, NOW);
  db.prepare(`
    INSERT INTO provider_turns (
      id, run_id, provider, model, model_configuration_hash,
      status, started_at
    ) VALUES (?, ?, 'openrouter', ?, ?, 'started', ?)
  `).run(
    PROVIDER_TURN_ID,
    RUN_ID,
    MODEL,
    MODEL_CONFIGURATION_HASH,
    NOW,
  );
}

function prepared() {
  const catalog = buildProviderAdvisoryCandidateCatalog({
    planningRequestId: PLANNING_REQUEST_ID,
    contractHash: "a".repeat(64),
    policyHash: "b".repeat(64),
    contextPackId: CONTEXT_PACK_ID,
    allowedTargets: [TARGET],
    allowedActionClassIds: ["active_host_discovery"],
    prohibitedActionClassIds: [],
    allowedAgentIds: ["ReconScout"],
    maximumSteps: 4,
    candidates: [{
      publicSummary: {
        phase: "Reachability",
        purpose:
          "Confirm whether the approved environment answers one bounded probe.",
      },
      step: {
        phase: "Reconnaissance",
        title: "Confirm host reachability",
        objective: "Record one attributable reachability observation.",
        explanation:
          "The local runtime performs one bounded check before deeper work.",
        rationale:
          "A current observation prevents stale assumptions from driving the plan.",
        successCriteria: ["Retain the current reachability result."],
        dependencyOrdinals: [],
        assignedAgentId: "ReconScout",
        riskClass: "medium",
        reversibility: "Read-only; target state is not changed.",
        action: {
          actionType: "kali:ping-host-liveness",
          actionClass: "active_host_discovery",
          target: TARGET,
          arguments: {
            schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
            executionBinding: "reviewed_local_process",
            toolId: "kali:ping-host-liveness",
            parameters: { exactTarget: TARGET },
          },
          intentSummary: "Confirm the exact authorized host once.",
          kind: "tool",
          idempotent: true,
          destructive: false,
        },
      },
      requiredEvidenceTypeIds: ["asset_discovery_proof"],
    }],
  });
  return prepareProviderAdvisoryBrief({
    catalog,
    providerId: "openrouter",
    modelId: MODEL,
    createdAt: NOW,
  });
}

function input(receipt = prepared().exposureReceipt) {
  return {
    receipt,
    planningRequestId: PLANNING_REQUEST_ID,
    missionId: MISSION_ID,
    runId: RUN_ID,
    contextPackId: CONTEXT_PACK_ID,
    providerTurnId: PROVIDER_TURN_ID,
    modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    planningDisclosureMode: "sanitized_internal",
  } as const;
}

describe("ProviderAdvisoryExposureRepository", () => {
  test("persists one exact advisory receipt and authorizes only its bound request", async () => {
    const db = database();
    seed(db);
    const repository = new ProviderAdvisoryExposureRepository(db);
    const receipt = prepared().exposureReceipt;

    const first = repository.persist(input(receipt));
    const second = repository.persist(input(receipt));

    expect(second).toEqual(first);
    expect(first).toMatchObject({
      exposureReceiptId: receipt.id,
      contextPackId: CONTEXT_PACK_ID,
      providerTurnId: PROVIDER_TURN_ID,
      providerId: "openrouter",
      modelId: MODEL,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      planningRequestId: PLANNING_REQUEST_ID,
      planningDisclosureMode: "sanitized_internal",
    });
    expect(db.prepare(`
      SELECT
        provider_turn_id AS providerTurnId,
        context_pack_id AS contextPackId,
        advisory_planning_request_id AS planningRequestId,
        planning_disclosure_mode AS planningDisclosureMode,
        advisory_identity_hash AS advisoryIdentityHash,
        request_authorized_at AS authorizedAt,
        selected_context_ids_json AS selectedContext
      FROM provider_exposure_receipts WHERE id = ?
    `).get(receipt.id)).toEqual({
      providerTurnId: PROVIDER_TURN_ID,
      contextPackId: CONTEXT_PACK_ID,
      planningRequestId: PLANNING_REQUEST_ID,
      planningDisclosureMode: "sanitized_internal",
      advisoryIdentityHash: first.advisoryIdentityHash,
      authorizedAt: null,
      selectedContext: JSON.stringify(receipt.selectedContextIds),
    });
    expect(first.advisoryIdentityHash).toBe(
      providerAdvisoryDisclosureIdentityHash({
        exposureReceiptId: receipt.id,
        planningRequestId: PLANNING_REQUEST_ID,
        missionId: MISSION_ID,
        runId: RUN_ID,
        contextPackId: CONTEXT_PACK_ID,
        providerTurnId: PROVIDER_TURN_ID,
        providerId: "openrouter",
        modelId: MODEL,
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
        disclosurePolicyVersion: receipt.disclosurePolicyVersion,
        planningDisclosureMode: "sanitized_internal",
        exposedPayloadHash: receipt.exposedPayloadHash,
      }),
    );

    const auditor = new OpenRouterProviderRequestAuditor({
      database: db,
      now: () => new Date(NOW),
      maximumReceiptAgeMs: 60_000,
    });
    await expect(auditor.authorize({
      providerId: "openrouter",
      exposure: {
        exposureReceiptId: receipt.id,
        contextPackId: CONTEXT_PACK_ID,
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
        planningDisclosureMode: first.planningDisclosureMode,
        advisoryIdentityHash: first.advisoryIdentityHash,
      },
      requestedModel: MODEL,
      endpoint: "https://openrouter.ai/api/v1/chat/completions",
      requestContractVersion: "ti-scale.openrouter-structured-request.v1",
      requestBodyHash: "d".repeat(64),
      requestBodyBytes: 512,
    })).resolves.toMatchObject({
      authorized: true,
      providerTurnId: PROVIDER_TURN_ID,
      exposureReceiptId: receipt.id,
      planningDisclosureMode: "sanitized_internal",
      advisoryIdentityHash: first.advisoryIdentityHash,
    });

    const binding = new ProviderAdvisoryRequestBindingRepository(db)
      .requireBound({
        exposureReceiptId: receipt.id,
        providerTurnId: PROVIDER_TURN_ID,
        contextPackId: CONTEXT_PACK_ID,
        modelId: MODEL,
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
        planningDisclosureMode: first.planningDisclosureMode,
        advisoryIdentityHash: first.advisoryIdentityHash,
      });
    expect(binding).toMatchObject({
      planningRequestId: PLANNING_REQUEST_ID,
      planningDisclosureMode: "sanitized_internal",
      advisoryIdentityHash: first.advisoryIdentityHash,
      requestBodyHash: "d".repeat(64),
    });
  });

  test("rejects a turn or Context Pack outside the exact Autonomous binding", () => {
    const db = database();
    seed(db);
    const repository = new ProviderAdvisoryExposureRepository(db);

    db.prepare("UPDATE provider_turns SET model = 'other/model' WHERE id = ?")
      .run(PROVIDER_TURN_ID);
    expect(() => repository.persist(input())).toThrow(
      new ProviderAdvisoryPlanningError(
        "provider_advisory_provider_turn_mismatch",
        "The advisory disclosure does not match one canonical started planning-provider turn.",
        "policy_drift",
        false,
      ),
    );

    db.prepare("UPDATE provider_turns SET model = ? WHERE id = ?")
      .run(MODEL, PROVIDER_TURN_ID);
    db.prepare("UPDATE memory_context_packs SET journey = 'guided' WHERE id = ?")
      .run(CONTEXT_PACK_ID);
    expect(() => repository.persist(input())).toThrow(
      new ProviderAdvisoryPlanningError(
        "provider_advisory_context_pack_mismatch",
        "The advisory disclosure Context Pack does not belong to this exact Autonomous mission and run.",
        "policy_drift",
        false,
      ),
    );
    expect(db.prepare(
      "SELECT COUNT(*) AS count FROM provider_exposure_receipts",
    ).get()).toEqual({ count: 0 });
  });

  test("rejects a tampered deterministic disclosure receipt before persistence", () => {
    const db = database();
    seed(db);
    const repository = new ProviderAdvisoryExposureRepository(db);
    const receipt = prepared().exposureReceipt;
    const tampered = {
      ...receipt,
      selectedContextIds: [...receipt.selectedContextIds, "candidate_tampered"],
    };

    expect(() => repository.persist(input(tampered))).toThrow(
      new ProviderAdvisoryPlanningError(
        "provider_advisory_exposure_integrity_failed",
        "The advisory disclosure receipt is blocked or does not match the local planning exposure policy.",
        "disclosure_denied",
        false,
      ),
    );
    expect(db.prepare(
      "SELECT COUNT(*) AS count FROM provider_exposure_receipts",
    ).get()).toEqual({ count: 0 });
  });

  test("rejects disclosure-mode replay drift and makes the persisted identity tuple immutable", () => {
    const db = database();
    seed(db);
    const repository = new ProviderAdvisoryExposureRepository(db);
    const persisted = repository.persist(input());

    expect(() => repository.persist({
      ...input(),
      planningDisclosureMode: "public_only",
    })).toThrow(
      new ProviderAdvisoryPlanningError(
        "provider_advisory_exposure_receipt_conflict",
        "The deterministic advisory exposure identity is already bound to different canonical records.",
        "policy_drift",
        false,
      ),
    );
    expect(() => db.prepare(`
      UPDATE provider_exposure_receipts
      SET planning_disclosure_mode = 'public_only'
      WHERE id = ?
    `).run(persisted.exposureReceiptId)).toThrow(
      "Provider advisory disclosure identity is immutable",
    );
  });

  test("request binding fails closed when the exact mode or identity does not match", async () => {
    const db = database();
    seed(db);
    const persisted = new ProviderAdvisoryExposureRepository(db)
      .persist(input());
    const auditor = new OpenRouterProviderRequestAuditor({
      database: db,
      now: () => new Date(NOW),
      maximumReceiptAgeMs: 60_000,
    });
    await auditor.authorize({
      providerId: "openrouter",
      exposure: {
        exposureReceiptId: persisted.exposureReceiptId,
        contextPackId: persisted.contextPackId,
        modelConfigurationHash: persisted.modelConfigurationHash,
        planningDisclosureMode: persisted.planningDisclosureMode,
        advisoryIdentityHash: persisted.advisoryIdentityHash,
      },
      requestedModel: MODEL,
      endpoint: "https://openrouter.ai/api/v1/chat/completions",
      requestContractVersion: "ti-scale.openrouter-structured-request.v1",
      requestBodyHash: "e".repeat(64),
      requestBodyBytes: 384,
    });
    const repository = new ProviderAdvisoryRequestBindingRepository(db);
    const base = {
      exposureReceiptId: persisted.exposureReceiptId,
      providerTurnId: persisted.providerTurnId,
      contextPackId: persisted.contextPackId,
      modelId: persisted.modelId,
      modelConfigurationHash: persisted.modelConfigurationHash,
      advisoryIdentityHash: persisted.advisoryIdentityHash,
    };

    expect(() => repository.requireBound({
      ...base,
      planningDisclosureMode: "public_only",
    })).toThrow("The advisory result has no matching durable exact-request authorization.");
    expect(() => repository.requireBound({
      ...base,
      planningDisclosureMode: persisted.planningDisclosureMode,
      advisoryIdentityHash: "f".repeat(64),
    })).toThrow("The advisory result has no matching durable exact-request authorization.");
  });

  test("keeps historical non-advisory research receipts compatible and forbids them from claiming advisory identity", () => {
    const db = database();
    db.prepare(`
      INSERT INTO provider_exposure_receipts (
        id, provider_id, model_id, experiment_id,
        disclosure_policy_version, input_classification,
        selected_context_ids_json, rejected_context_ids_json,
        sanitization_actions_json, exposed_payload_hash,
        blocked, block_reason, created_at
      ) VALUES (
        'receipt-legacy-research', 'openrouter', 'openai/gpt-5.2',
        'experiment-historical',
        'research-exposure-v1', 'sanitized_research_brief',
        '[]', '[]', '[]', ?, 0, NULL, ?
      )
    `).run("1".repeat(64), NOW);

    expect(db.prepare(`
      SELECT
        advisory_planning_request_id AS planningRequestId,
        planning_disclosure_mode AS planningDisclosureMode,
        advisory_identity_hash AS advisoryIdentityHash
      FROM provider_exposure_receipts
      WHERE id = 'receipt-legacy-research'
    `).get()).toEqual({
      planningRequestId: null,
      planningDisclosureMode: null,
      advisoryIdentityHash: null,
    });
    expect(() => db.prepare(`
      INSERT INTO provider_exposure_receipts (
        id, provider_id, model_id, experiment_id,
        disclosure_policy_version, input_classification,
        selected_context_ids_json, rejected_context_ids_json,
        sanitization_actions_json, exposed_payload_hash,
        blocked, block_reason, created_at,
        advisory_planning_request_id, planning_disclosure_mode,
        advisory_identity_hash
      ) VALUES (
        'receipt-invalid-research', 'openrouter', 'openai/gpt-5.2',
        'experiment-historical',
        'research-exposure-v1', 'sanitized_research_brief',
        '[]', '[]', '[]', ?, 0, NULL, ?,
        'planning-request-invalid', 'public_only', ?
      )
    `).run("2".repeat(64), NOW, "3".repeat(64))).toThrow(
      "Non-advisory receipts cannot claim a planning disclosure identity",
    );
  });
});

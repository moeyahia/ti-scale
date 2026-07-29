import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  providerAdvisorySafeStop,
  type PrepareProviderAdvisoryBrainContextInput,
  type ProviderAdvisoryRuntimePort,
  type ProviderAdvisoryRuntimeRequest,
} from "../../autonomous-planning";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  getMemoryControlPolicy,
  MemoryRepository,
  updateMemoryControlPolicy,
} from "../../memory";
import {
  OpenRouterPlanningError,
  type OpenRouterModelAttestation,
  type OpenRouterReadinessRuntimeSnapshot,
  StructuredJsonCall,
  StructuredJsonProviderClient,
  StructuredJsonResult,
} from "../../providers/openrouter";
import {
  createAutonomousProviderAdvisoryComposition,
  createReadinessGatedProviderAdvisory,
} from "../AutonomousProviderAdvisoryComposition";

const serverEntrypoint = readFileSync(
  new URL("../../index.ts", import.meta.url),
  "utf8",
);

const NOW = new Date("2026-07-28T08:30:00.000Z");
const MODEL = "openai/gpt-5.2";
const MODEL_HASH = "a".repeat(64);
const RECEIPT_ID = "provider-request-readiness";
const CONTRACT_ID = "contract-provider-readiness";
const CONTEXT_NODE_ID = "memory-provider-readiness";
let providerCalls = 0;

const countedProvider: StructuredJsonProviderClient = {
  async callStructuredJson<T>(
    _input: StructuredJsonCall<T>,
  ): Promise<StructuredJsonResult<T>> {
    providerCalls += 1;
    throw new Error("The composition test must not contact a provider");
  },
};

function readySnapshot(
  overrides: Partial<OpenRouterReadinessRuntimeSnapshot> = {},
): OpenRouterReadinessRuntimeSnapshot {
  return {
    status: "ready",
    configured: true,
    authenticated: true,
    callable: true,
    supportsGuided: true,
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: true,
    reportsExactCostUsage: true,
    requestedModel: MODEL,
    returnedModel: MODEL,
    modelConfigurationHash: MODEL_HASH,
    completionProbeReceiptId: RECEIPT_ID,
    lastCheckedAt: NOW.toISOString(),
    attestedAt: NOW.toISOString(),
    expiresAt: "2026-07-28T08:35:00.000Z",
    reason: "Exact provider readiness is current.",
    ...overrides,
  };
}

function attestation(
  overrides: Partial<OpenRouterModelAttestation> = {},
): OpenRouterModelAttestation {
  return {
    schemaVersion: "ti-scale.openrouter-model-attestation.v2",
    providerId: "openrouter",
    model: MODEL,
    modelConfigurationHash: MODEL_HASH,
    authenticated: true,
    keyEligibility: "verified_completion_key",
    metadataSupportsGuided: true,
    callable: true,
    callabilityVerification: "audited_content_free_completion",
    supportsGuided: true,
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: true,
    reportsExactCostUsage: true,
    contextLength: 65_536,
    supportedParameters: [
      "response_format",
      "structured_outputs",
      "tool_choice",
      "tools",
    ],
    pricing: {
      promptUsdPerToken: "0.000001",
      completionUsdPerToken: "0.000002",
      provenance: "advertised_model_metadata",
    },
    completionProbeReceiptId: RECEIPT_ID,
    completionReturnedModel: MODEL,
    attestedAt: NOW.toISOString(),
    expiresAt: "2026-07-28T08:35:00.000Z",
    latencyMs: 10,
    ...overrides,
  };
}

function request(): ProviderAdvisoryRuntimeRequest {
  return {
    missionId: "mission-provider-readiness",
    runId: "run-provider-readiness",
    providerTurnId: "turn-provider-readiness",
    signedSelection: {
      route: "provider_advisory",
      agentId: "MissionPlanner",
      primaryConfigurationId: "modelcfg-provider-readiness",
      fallbackConfigurationId: null,
      enforcementMode: "advisor_only",
      disclosureClass: "sanitized_internal",
      executionAuthority: "none",
    },
    resolvedBinding: {
      agentId: "MissionPlanner",
      primaryConfigurationId: "modelcfg-provider-readiness",
      providerId: "openrouter",
      modelId: MODEL,
      modelConfigurationHash: MODEL_HASH,
      disclosureClass: "sanitized_internal",
      enforcementMode: "advisor_only",
      executionAuthority: "none",
    },
    candidateCatalog: {
      planningRequestId: "planning-request-provider-readiness",
      contractHash: "b".repeat(64),
      policyHash: "c".repeat(64),
      contextPackId: "context-provider-readiness",
      allowedTargets: [],
      allowedActionClassIds: [],
      prohibitedActionClassIds: [],
      allowedAgentIds: ["MissionPlanner"],
      maximumSteps: 1,
      candidates: [],
    },
    createdAt: NOW.toISOString(),
    contextItems: [],
  };
}

function seedProviderBrainContext(database: ReturnType<
  typeof createDatabaseConnection
>): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, memory_policy_json, created_by, created_at, updated_at,
      control_plane
    ) VALUES (?, 'Provider readiness fixture',
      'Order one bounded local plan', 'autonomous', 'active', 'verified',
      'engagement-provider-readiness', '{}', 'operator:test', ?, ?,
      'ti_scale')
  `).run(
    request().missionId,
    NOW.toISOString(),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{}', '{}', '[]', ?,
      'operator:test', ?, ?)
  `).run(
    CONTRACT_ID,
    request().missionId,
    request().candidateCatalog.contractHash,
    JSON.stringify({
      planningSelection: request().signedSelection,
      contextNodeIds: [CONTEXT_NODE_ID],
    }),
    JSON.stringify(["confirmed_preferences"]),
    NOW.toISOString(),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id,
      contract_version_bound, contract_hash_bound, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version,
      control_plane
    ) VALUES (?, ?, 'autonomous', 'planning', ?, 1, ?, 0,
      'Await provider readiness', '{}', '{}', ?, ?, 1, 'ti_scale')
  `).run(
    request().runId,
    request().missionId,
    CONTRACT_ID,
    request().candidateCatalog.contractHash,
    NOW.toISOString(),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json,
      release_data_class, created_by, created_at
    ) VALUES (?, ?, ?, 'autonomous', 'Provider readiness context',
      'bounded planning knowledge', ?, 6, '{}', 'canonical',
      'mission-planner', ?)
  `).run(
    request().candidateCatalog.contextPackId,
    request().missionId,
    request().runId,
    JSON.stringify({
      journey: "autonomous",
      engagementId: "engagement-provider-readiness",
      missionId: request().missionId,
      allowGlobal: false,
    }),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO memory_nodes (
      id, node_type, title, summary, body, scope, engagement_id, mission_id,
      sensitivity, confidence, lifecycle_status, confirmation_state,
      provenance_json, author_type, author_id, version,
      retention_policy_json, expires_at, pinned, created_at, updated_at
    ) VALUES (?, 'preference', 'Bounded verification order',
      'Collect current evidence before choosing an intrusive alternative.', '',
      'mission', 'engagement-provider-readiness', ?, 'internal', 1,
      'verified', 'confirmed', ?, 'operator', 'operator:test', 1, ?,
      NULL, 0, ?, ?)
  `).run(
    CONTEXT_NODE_ID,
    request().missionId,
    JSON.stringify({
      method: "derived",
      explanation: "Explicitly reviewed fixture knowledge.",
      sources: [{
        sourceType: "test",
        sourceId: CONTEXT_NODE_ID,
        acquiredAt: NOW.toISOString(),
      }],
    }),
    JSON.stringify({
      allowAutonomous: true,
      publicProviderDisclosure: "sanitized",
    }),
    NOW.toISOString(),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO memory_context_items (
      context_pack_id, node_id, rank, retrieval_score, used,
      relevance_reason, influence_summary, ignored_reason, corrected
    ) VALUES (?, ?, 1, 1, 0,
      'Relevant to bounded plan ordering.', NULL, 'Not evaluated', 0)
  `).run(
    request().candidateCatalog.contextPackId,
    CONTEXT_NODE_ID,
  );
}

function contextPreparation(): PrepareProviderAdvisoryBrainContextInput {
  return Object.freeze({
    missionId: request().missionId,
    runId: request().runId,
    contextPackId: request().candidateCatalog.contextPackId,
    retrievedByActorId: "mission-planner",
    actorId: "MissionPlanner",
    disclosureClass: "sanitized_internal",
    maximumItems: 6,
    maximumBytes: 4_000,
  });
}

function withPreparedContext(
  composition: ReturnType<typeof createAutonomousProviderAdvisoryComposition>,
): ProviderAdvisoryRuntimeRequest {
  const preparation = contextPreparation();
  const prepared = composition.providerPlanningContext.prepare(preparation);
  return Object.freeze({
    ...request(),
    contextItems: prepared.items,
    brainContextSnapshot: Object.freeze({
      preparation,
      inputFingerprint: prepared.telemetry.inputFingerprint,
      outputHash: prepared.telemetry.outputHash,
    }),
  });
}

describe("standalone Autonomous provider-advisory composition", () => {
  test("mounts the advisor and filtered Brain port as one no-authority boundary", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const composition = createAutonomousProviderAdvisoryComposition({
        database,
        providerClient: countedProvider,
        readReadiness: () => readySnapshot(),
        readAttestation: () => attestation(),
        now: () => NOW,
      });

      expect(composition.providerAdvisory.route).toBe("provider_advisory");
      expect(composition.providerAdvisory.executionAuthority).toBe("none");
      expect(typeof composition.providerAdvisory.plan).toBe("function");
      expect(typeof composition.providerPlanningContext.prepare).toBe("function");
      expect(Object.isFrozen(composition)).toBe(true);
    } finally {
      database.close();
    }
  });

  test("safe-stops before exposure or provider contact when readiness is degraded", async () => {
    providerCalls = 0;
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const composition = createAutonomousProviderAdvisoryComposition({
        database,
        providerClient: countedProvider,
        readReadiness: () => readySnapshot({
          status: "degraded",
          callable: false,
          supportsGuided: false,
          reportsExactTokenUsage: false,
          reportsExactCostUsage: false,
          completionProbeReceiptId: undefined,
          failureCode: "openrouter_attestation_expired",
          remediation: "Refresh OpenRouter readiness.",
        }),
        readAttestation: () => undefined,
        now: () => NOW,
      });

      const outcome = await composition.providerAdvisory.plan(
        request(),
        new AbortController().signal,
      );
      expect(outcome.status).toBe("safe_stopped");
      if (outcome.status !== "safe_stopped") throw new Error("Expected safe stop");
      expect(outcome.safeStop.code).toBe("openrouter_attestation_expired");
      expect(outcome.safeStop.category).toBe("provider_unavailable");
      expect(providerCalls).toBe(0);
      expect(database.prepare(
        "SELECT COUNT(*) AS count FROM provider_exposure_receipts",
      ).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("rejects exact-model or attestation drift without delegating", async () => {
    let delegated = 0;
    const delegate: ProviderAdvisoryRuntimePort = {
      route: "provider_advisory",
      executionAuthority: "none",
      async plan(input) {
        delegated += 1;
        return providerAdvisorySafeStop(
          input,
          new OpenRouterPlanningError(
            "delegate_called",
            "The delegate was called.",
            {
              status: 503,
              category: "provider_unavailable",
              retryable: true,
            },
          ),
        );
      },
    };
    const gated = createReadinessGatedProviderAdvisory({
      delegate,
      readReadiness: () => readySnapshot(),
      readAttestation: () => attestation({
        modelConfigurationHash: "d".repeat(64),
      }),
      now: () => NOW,
    });

    const outcome = await gated.plan(request(), new AbortController().signal);
    expect(outcome.status).toBe("safe_stopped");
    if (outcome.status !== "safe_stopped") throw new Error("Expected safe stop");
    expect(outcome.safeStop.code)
      .toBe("provider_advisory_readiness_binding_mismatch");
    expect(outcome.safeStop.category).toBe("audit_unavailable");
    expect(delegated).toBe(0);
  });

  test("delegates only when the full live attestation matches the signed binding", async () => {
    let delegated = 0;
    let attestedReturnedModel: string | undefined;
    const delegate: ProviderAdvisoryRuntimePort = {
      route: "provider_advisory",
      executionAuthority: "none",
      async plan(input) {
        delegated += 1;
        attestedReturnedModel =
          input.resolvedBinding.attestedReturnedModel;
        return providerAdvisorySafeStop(
          input,
          new OpenRouterPlanningError(
            "delegate_called",
            "The matching delegate was called.",
            {
              status: 503,
              category: "provider_unavailable",
              retryable: true,
            },
          ),
        );
      },
    };
    const gated = createReadinessGatedProviderAdvisory({
      delegate,
      readReadiness: () => readySnapshot(),
      readAttestation: () => attestation(),
      now: () => NOW,
    });

    const outcome = await gated.plan(request(), new AbortController().signal);
    expect(outcome.status).toBe("safe_stopped");
    if (outcome.status !== "safe_stopped") throw new Error("Expected delegate outcome");
    expect(outcome.safeStop.code).toBe("delegate_called");
    expect(delegated).toBe(1);
    expect(attestedReturnedModel).toBe(MODEL);
  });

  test("waits only a provider-selected call for an in-flight readiness proof", async () => {
    let delegated = 0;
    let waited = 0;
    let liveReadiness = readySnapshot({
      status: "probing",
      authenticated: false,
      callable: false,
      supportsGuided: false,
      reportsExactTokenUsage: false,
      reportsExactCostUsage: false,
    });
    const delegate: ProviderAdvisoryRuntimePort = {
      route: "provider_advisory",
      executionAuthority: "none",
      async plan(input) {
        delegated += 1;
        return providerAdvisorySafeStop(
          input,
          new OpenRouterPlanningError(
            "delegate_called_after_readiness",
            "The delegate was called after readiness.",
            {
              status: 503,
              category: "provider_unavailable",
              retryable: true,
            },
          ),
        );
      },
    };
    const gated = createReadinessGatedProviderAdvisory({
      delegate,
      readReadiness: () => liveReadiness,
      readAttestation: () => attestation(),
      async waitForReadiness() {
        waited += 1;
        liveReadiness = readySnapshot();
        return liveReadiness;
      },
      now: () => NOW,
    });

    const outcome = await gated.plan(request(), new AbortController().signal);
    expect(outcome.status).toBe("safe_stopped");
    if (outcome.status !== "safe_stopped") throw new Error("Expected delegate outcome");
    expect(outcome.safeStop.code).toBe("delegate_called_after_readiness");
    expect(waited).toBe(1);
    expect(delegated).toBe(1);
  });

  test("preserves timeout diagnosis and rejects a missing or mismatched attestation", async () => {
    let delegated = 0;
    const delegate: ProviderAdvisoryRuntimePort = {
      route: "provider_advisory",
      executionAuthority: "none",
      async plan(input) {
        delegated += 1;
        return providerAdvisorySafeStop(
          input,
          new OpenRouterPlanningError(
            "delegate_must_not_run",
            "The delegate must not run.",
            {
              status: 503,
              category: "provider_unavailable",
              retryable: true,
            },
          ),
        );
      },
    };
    const timedOut = createReadinessGatedProviderAdvisory({
      delegate,
      readReadiness: () => readySnapshot({
        status: "degraded",
        callable: false,
        supportsGuided: false,
        reportsExactTokenUsage: false,
        reportsExactCostUsage: false,
        failureCode: "openrouter_readiness_timeout",
        failureCategory: "timeout",
        failureRetryable: true,
        failureHttpStatus: 504,
      }),
      readAttestation: () => undefined,
      now: () => NOW,
    });
    const timeoutOutcome = await timedOut.plan(
      request(),
      new AbortController().signal,
    );
    expect(timeoutOutcome.status).toBe("safe_stopped");
    if (timeoutOutcome.status !== "safe_stopped") throw new Error("Expected timeout");
    expect(timeoutOutcome.safeStop).toMatchObject({
      code: "openrouter_readiness_timeout",
      category: "timeout",
      retryable: true,
      httpStatus: 504,
    });

    for (const readAttestation of [
      () => undefined,
      () => attestation({ completionProbeReceiptId: "different-receipt" }),
    ]) {
      const gated = createReadinessGatedProviderAdvisory({
        delegate,
        readReadiness: () => readySnapshot(),
        readAttestation,
        now: () => NOW,
      });
      const outcome = await gated.plan(
        request(),
        new AbortController().signal,
      );
      expect(outcome.status).toBe("safe_stopped");
    }
    expect(delegated).toBe(0);
  });

  test("revoked Autonomous Brain consent during readiness produces zero exposure and zero provider calls", async () => {
    providerCalls = 0;
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      seedProviderBrainContext(database);
      let liveReadiness = readySnapshot({
        status: "probing",
        authenticated: false,
        callable: false,
        supportsGuided: false,
        reportsExactTokenUsage: false,
        reportsExactCostUsage: false,
      });
      let announceWait!: () => void;
      const waitStarted = new Promise<void>((resolve) => {
        announceWait = resolve;
      });
      let releaseReadiness!: (
        value: OpenRouterReadinessRuntimeSnapshot,
      ) => void;
      const readiness = new Promise<OpenRouterReadinessRuntimeSnapshot>(
        (resolve) => {
          releaseReadiness = resolve;
        },
      );
      const composition = createAutonomousProviderAdvisoryComposition({
        database,
        providerClient: countedProvider,
        readReadiness: () => liveReadiness,
        readAttestation: () => attestation(),
        waitForReadiness() {
          announceWait();
          return readiness;
        },
        now: () => NOW,
      });
      const preparedRequest = withPreparedContext(composition);
      const pending = composition.providerAdvisory.plan(
        preparedRequest,
        new AbortController().signal,
      );
      await waitStarted;

      const current = getMemoryControlPolicy(database);
      updateMemoryControlPolicy({
        database,
        expectedVersion: current.version,
        actor: "operator:test",
        now: NOW.toISOString(),
        policy: {
          enabled: current.enabled,
          personalPreferencePolicy: current.personalPreferencePolicy,
          operationalMemoryEnabled: current.operationalMemoryEnabled,
          engagementIsolation: true,
          defaultRetentionDays: current.defaultRetentionDays,
          autonomousUse: false,
          guidedUse: current.guidedUse,
          obsidianSyncScope: current.obsidianSyncScope,
          secretsNeverRetained: true,
        },
      });
      liveReadiness = readySnapshot();
      releaseReadiness(liveReadiness);

      const outcome = await pending;
      expect(outcome.status).toBe("safe_stopped");
      if (outcome.status !== "safe_stopped") {
        throw new Error("Expected revoked-consent safe stop");
      }
      expect(outcome.safeStop).toMatchObject({
        code: "provider_advisory_autonomous_memory_use_revoked",
        category: "audit_unavailable",
        retryable: false,
      });
      expect(providerCalls).toBe(0);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM provider_exposure_receipts
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("forgetting a Brain node during readiness invalidates the complete disclosure generation", async () => {
    providerCalls = 0;
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      seedProviderBrainContext(database);
      let liveReadiness = readySnapshot({
        status: "probing",
        authenticated: false,
        callable: false,
        supportsGuided: false,
        reportsExactTokenUsage: false,
        reportsExactCostUsage: false,
      });
      let announceWait!: () => void;
      const waitStarted = new Promise<void>((resolve) => {
        announceWait = resolve;
      });
      let releaseReadiness!: (
        value: OpenRouterReadinessRuntimeSnapshot,
      ) => void;
      const readiness = new Promise<OpenRouterReadinessRuntimeSnapshot>(
        (resolve) => {
          releaseReadiness = resolve;
        },
      );
      const composition = createAutonomousProviderAdvisoryComposition({
        database,
        providerClient: countedProvider,
        readReadiness: () => liveReadiness,
        readAttestation: () => attestation(),
        waitForReadiness() {
          announceWait();
          return readiness;
        },
        now: () => NOW,
      });
      const preparedRequest = withPreparedContext(composition);
      const pending = composition.providerAdvisory.plan(
        preparedRequest,
        new AbortController().signal,
      );
      await waitStarted;

      new MemoryRepository(database, { clock: () => NOW }).forgetNode(
        CONTEXT_NODE_ID,
        "operator:test",
        "Forget this memory while provider readiness is pending.",
      );
      liveReadiness = readySnapshot();
      releaseReadiness(liveReadiness);

      const outcome = await pending;
      expect(outcome.status).toBe("safe_stopped");
      if (outcome.status !== "safe_stopped") {
        throw new Error("Expected context-generation safe stop");
      }
      expect(outcome.safeStop).toMatchObject({
        code: "provider_advisory_brain_context_changed_during_readiness",
        category: "audit_unavailable",
        retryable: false,
      });
      expect(providerCalls).toBe(0);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM provider_exposure_receipts
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("cancellation while readiness is pending never reaches context, exposure, or provider work", async () => {
    providerCalls = 0;
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      let announceWait!: () => void;
      const waitStarted = new Promise<void>((resolve) => {
        announceWait = resolve;
      });
      let releaseReadiness!: (
        value: OpenRouterReadinessRuntimeSnapshot,
      ) => void;
      const readiness = new Promise<OpenRouterReadinessRuntimeSnapshot>(
        (resolve) => {
          releaseReadiness = resolve;
        },
      );
      const composition = createAutonomousProviderAdvisoryComposition({
        database,
        providerClient: countedProvider,
        readReadiness: () => readySnapshot({
          status: "probing",
          authenticated: false,
          callable: false,
          supportsGuided: false,
          reportsExactTokenUsage: false,
          reportsExactCostUsage: false,
        }),
        readAttestation: () => attestation(),
        waitForReadiness() {
          announceWait();
          return readiness;
        },
        now: () => NOW,
      });
      const controller = new AbortController();
      const pending = composition.providerAdvisory.plan(
        request(),
        controller.signal,
      );
      await waitStarted;
      controller.abort();

      const outcome = await pending;
      releaseReadiness(readySnapshot());
      await Promise.resolve();
      expect(outcome.status).toBe("safe_stopped");
      if (outcome.status !== "safe_stopped") {
        throw new Error("Expected cancellation safe stop");
      }
      expect(outcome.safeStop).toMatchObject({
        code: "openrouter_provider_advisory_cancelled",
        category: "cancelled",
        retryable: false,
      });
      expect(providerCalls).toBe(0);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM provider_exposure_receipts
      `).get()).toEqual({ count: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'provider_advisory.brain_context.prepared'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("removes the abort listener when waitForReadiness throws synchronously", async () => {
    let delegated = 0;
    let liveReadiness = readySnapshot({
      status: "probing",
      authenticated: false,
      callable: false,
      supportsGuided: false,
      reportsExactTokenUsage: false,
      reportsExactCostUsage: false,
    });
    const delegate: ProviderAdvisoryRuntimePort = {
      route: "provider_advisory",
      executionAuthority: "none",
      async plan(input) {
        delegated += 1;
        return providerAdvisorySafeStop(
          input,
          new Error("The delegate must not run"),
        );
      },
    };
    const controller = new AbortController();
    const originalAdd = controller.signal.addEventListener.bind(
      controller.signal,
    );
    const originalRemove = controller.signal.removeEventListener.bind(
      controller.signal,
    );
    let added = 0;
    let removed = 0;
    Object.defineProperty(controller.signal, "addEventListener", {
      configurable: true,
      value: (...args: Parameters<AbortSignal["addEventListener"]>) => {
        added += 1;
        return originalAdd(...args);
      },
    });
    Object.defineProperty(controller.signal, "removeEventListener", {
      configurable: true,
      value: (...args: Parameters<AbortSignal["removeEventListener"]>) => {
        removed += 1;
        return originalRemove(...args);
      },
    });
    const gated = createReadinessGatedProviderAdvisory({
      delegate,
      readReadiness: () => liveReadiness,
      readAttestation: () => undefined,
      waitForReadiness() {
        liveReadiness = readySnapshot({
          status: "degraded",
          callable: false,
          supportsGuided: false,
          reportsExactTokenUsage: false,
          reportsExactCostUsage: false,
          failureCode: "openrouter_readiness_sync_failure",
        });
        throw new Error("synchronous readiness failure");
      },
      now: () => NOW,
    });

    const outcome = await gated.plan(request(), controller.signal);
    expect(outcome.status).toBe("safe_stopped");
    if (outcome.status !== "safe_stopped") {
      throw new Error("Expected readiness safe stop");
    }
    expect(outcome.safeStop.code).toBe(
      "openrouter_readiness_sync_failure",
    );
    expect(added).toBe(1);
    expect(removed).toBe(1);
    expect(delegated).toBe(0);
  });

  test("wires both halves into the standalone lifecycle when OpenRouter is configured", () => {
    expect(serverEntrypoint).toContain(
      "createAutonomousProviderAdvisoryComposition(",
    );
    expect(serverEntrypoint).toContain(
      "providerAdvisory:",
    );
    expect(serverEntrypoint).toContain(
      "autonomousProviderAdvisory.providerAdvisory",
    );
    expect(serverEntrypoint).toContain(
      "providerPlanningContext:",
    );
    expect(serverEntrypoint).toContain(
      "autonomousProviderAdvisory.providerPlanningContext",
    );
    expect(serverEntrypoint).toContain(
      "configuration: openRouterConfiguration",
    );
    expect(serverEntrypoint).toContain(
      "waitForReadiness: () => openRouterRuntime.refreshNow()",
    );
    expect(serverEntrypoint).not.toContain(
      "await openRouterRuntime.refreshNow()",
    );
  });
});

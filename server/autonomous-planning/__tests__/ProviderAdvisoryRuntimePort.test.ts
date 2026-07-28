import { afterEach, describe, expect, test } from "bun:test";
import type {
  PlannedStep,
  RuntimeModelBindingReceipt,
} from "../../command-runtime/types";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  type AutonomousPlanningSelection,
} from "../../model-config";
import {
  OpenRouterPlanningClient,
  OpenRouterProviderRequestAuditor,
  resolveOpenRouterModelConfiguration,
} from "../../providers/openrouter";
import type {
  ResearchSourceItem,
} from "../../research/LlmExposurePolicy";
import {
  PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION,
  ProviderAdvisoryPlanningError,
  ProviderAdvisoryRuntimeService,
  SignedAutonomousPlanningRoutePort,
  type BuildProviderAdvisoryCatalogInput,
  type ProviderAdvisoryResolvedPlanningBinding,
  type ProviderAdvisoryRuntimeRequest,
} from "../index";
import { sha256 } from "../../missions/canonical";

const NOW = "2026-07-28T19:30:00.000Z";
const MISSION_ID = "mission-provider-advisory-runtime";
const RUN_ID = "run-provider-advisory-runtime";
const CONTRACT_ID = "contract-provider-advisory-runtime";
const CONTRACT_HASH = "a".repeat(64);
const POLICY_HASH = "b".repeat(64);
const TARGET = "10.129.46.243";
const CONTEXT_PACK_ID = "context-provider-advisory-runtime";
const PROVIDER_TURN_ID = "provider-turn-advisory-runtime";
const PLANNING_REQUEST_ID = "planning-request-advisory-runtime";
const ADVISOR_AGENT_ID = "ReportSmith";
const ADVISOR_CONFIGURATION_ID = "configuration-advisor-runtime";
const ADVISOR_MODEL = "openai/gpt-5.2";
const EXECUTION_CONFIGURATION_ID = "configuration-recon-runtime";
const EXECUTION_MODEL_CONFIGURATION_HASH = "d".repeat(64);
const EXECUTION_PROVIDER_CONFIGURATION_HASH = "e".repeat(64);
const databases: SqliteDatabase[] = [];

const PROVIDER_SELECTION = Object.freeze({
  route: "provider_advisory",
  agentId: ADVISOR_AGENT_ID,
  primaryConfigurationId: ADVISOR_CONFIGURATION_ID,
  fallbackConfigurationId: null,
  enforcementMode: "advisor_only",
  disclosureClass: "sanitized_internal",
  executionAuthority: "none",
} satisfies AutonomousPlanningSelection);
const LOCAL_SELECTION = Object.freeze({
  route: "local_deterministic",
  plannerId: "ti-scale.local-autonomous-contract-planner.v1",
  enforcementMode: "local_policy",
  disclosureClass: "local_only",
  executionAuthority: "none",
} as const);

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function database(): SqliteDatabase {
  const value = createDatabaseConnection({ filename: ":memory:" });
  databases.push(value);
  migrateDatabase(value);
  return value;
}

function actionPolicy(
  selection: AutonomousPlanningSelection = PROVIDER_SELECTION,
) {
  return {
    allowedActionClasses: [
      "active_host_discovery",
      "cve_intelligence_applicability_validation",
    ],
    prohibitedActionClasses: [],
    destructivePolicy: "prohibited",
    boundedDestructiveTargets: [],
    evidenceRequirements: [
      "asset_discovery_proof",
      "cve_applicability",
      "service_version_fingerprint",
    ],
    notificationPolicy: "in_app_only",
    reportingFormat: "ti_scale_json",
    dataHandlingPolicy: "local_private",
    retentionPolicy: "operator_managed",
    providerPolicy: "automatic_enforcing_only",
    toolPolicy: "contract_allowlist",
    specialistAgentIds: ["ReconScout", "VulnIntel"],
    agentModelAssignments: [],
    contextNodeIds: [],
    planningSelection: selection,
  };
}

function seed(
  db: SqliteDatabase,
  selection: AutonomousPlanningSelection = PROVIDER_SELECTION,
): void {
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Provider advisory runtime fixture',
      'Inspect one exact authorized disposable lab host', 'autonomous',
      'active', 'verified', '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(MISSION_ID, NOW, NOW);
  db.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition,
      normalized_target, created_at
    ) VALUES ('target-provider-advisory-runtime', ?, ?, 'host',
      'allowed', ?, ?)
  `).run(MISSION_ID, TARGET, TARGET, NOW);
  for (const [id, role] of [
    [ADVISOR_AGENT_ID, "reporting"],
    ["ReconScout", "reconnaissance"],
    ["VulnIntel", "vulnerability-intelligence"],
  ] as const) {
    db.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, version, created_at, updated_at
      ) VALUES (?, ?, ?, 'available', 'fixture-1', ?, ?)
    `).run(id, role, id, NOW, NOW);
  }
  db.prepare(`
    INSERT INTO model_configurations (
      id, provider_id, model_id, context_policy_json, capabilities_json,
      context_limit, cost_class, latency_class, disclosure_class,
      enforcement_mode, auth_state, health_state, catalog_source,
      catalog_retrieved_at, configuration_source, created_at, updated_at,
      version
    ) VALUES (?, 'openrouter', ?, '{}', ?, 65536, 'standard',
      'standard', 'sanitized_internal', 'advisory_only', 'healthy',
      'healthy', 'test-live-catalog', ?, 'manual', ?, ?, 1)
  `).run(
    ADVISOR_CONFIGURATION_ID,
    ADVISOR_MODEL,
    JSON.stringify({
      displayName: "Advisory fixture model",
      structuredOutput: true,
      toolCalling: false,
      compatibleAgentIds: [ADVISOR_AGENT_ID],
      compatibleActionClassIds: [],
    }),
    NOW,
    NOW,
    NOW,
  );
  db.prepare(`
    INSERT INTO model_configurations (
      id, provider_id, model_id, context_policy_json, capabilities_json,
      context_limit, cost_class, latency_class, disclosure_class,
      enforcement_mode, auth_state, health_state, catalog_source,
      catalog_retrieved_at, configuration_source, created_at, updated_at,
      version
    ) VALUES (?, 'specialist-provider', 'specialist-execution-model',
      '{}', ?, 32768, 'standard', 'standard', 'public_only',
      'enforced', 'healthy', 'healthy', 'test-live-catalog', ?,
      'manual', ?, ?, 1)
  `).run(
    EXECUTION_CONFIGURATION_ID,
    JSON.stringify({
      displayName: "Specialist execution fixture model",
      structuredOutput: true,
      toolCalling: true,
      compatibleAgentIds: ["ReconScout", "VulnIntel"],
      compatibleActionClassIds: [
        "active_host_discovery",
        "cve_intelligence_applicability_validation",
      ],
    }),
    NOW,
    NOW,
    NOW,
  );
  db.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{}', '{}', '[]', '[]',
      'operator:test', ?, ?)
  `).run(
    CONTRACT_ID,
    MISSION_ID,
    CONTRACT_HASH,
    JSON.stringify(actionPolicy(selection)),
    NOW,
    NOW,
  );
  db.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id,
      contract_version_bound, contract_hash_bound, progress,
      status_reason, budget_json, budget_usage_json, started_at,
      created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'autonomous', 'planning', ?, 1, ?, 0,
      'Build an exact advisor-only plan', '{}', '{}', ?, ?, ?, 1,
      'ti_scale')
  `).run(
    RUN_ID,
    MISSION_ID,
    CONTRACT_ID,
    CONTRACT_HASH,
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
      'bounded provider advisory', '{}', 8, '{}', ?, ?)
  `).run(
    CONTEXT_PACK_ID,
    MISSION_ID,
    RUN_ID,
    ADVISOR_AGENT_ID,
    NOW,
  );
  if (selection.route === "provider_advisory") {
    db.prepare(`
      INSERT INTO provider_turns (
        id, run_id, provider, model, model_configuration_hash,
        agent_id, model_configuration_id, status, started_at
      ) VALUES (?, ?, 'openrouter', ?, ?, ?, ?, 'started', ?)
    `).run(
      PROVIDER_TURN_ID,
      RUN_ID,
      ADVISOR_MODEL,
      resolveOpenRouterModelConfiguration({
        model: ADVISOR_MODEL,
      }).configurationHash,
      ADVISOR_AGENT_ID,
      ADVISOR_CONFIGURATION_ID,
      NOW,
    );
  }
}

function runtimeModelBinding(
  agentId: "ReconScout" | "VulnIntel",
): RuntimeModelBindingReceipt {
  return {
    schemaVersion: "ti-scale.runtime-model-binding.v1",
    agentId,
    modelAssignmentId: `assignment-${agentId.toLowerCase()}`,
    modelConfigurationId: EXECUTION_CONFIGURATION_ID,
    modelConfigurationHash: EXECUTION_MODEL_CONFIGURATION_HASH,
    providerConfigurationHash: EXECUTION_PROVIDER_CONFIGURATION_HASH,
    providerId: "specialist-provider",
    modelId: "specialist-execution-model",
    reasoningEffort: null,
  };
}

function step(input: {
  readonly actionClass:
    | "active_host_discovery"
    | "cve_intelligence_applicability_validation";
  readonly actionType: string;
  readonly agentId: "ReconScout" | "VulnIntel";
  readonly title: string;
  readonly dependencyOrdinals?: readonly number[];
}): PlannedStep {
  return {
    phase: input.agentId === "ReconScout"
      ? "Reconnaissance"
      : "Analysis",
    title: input.title,
    objective: `Complete the bounded ${input.title.toLowerCase()} phase.`,
    explanation:
      "This locally reviewed step gathers one attributable observation.",
    rationale:
      "The local policy materialized the exact executable action before public advice.",
    successCriteria: ["Retain attributable output and provenance."],
    dependencyOrdinals: input.dependencyOrdinals ?? [],
    assignedAgentId: input.agentId,
    riskClass: input.actionClass === "active_host_discovery"
      ? "medium"
      : "low",
    reversibility: "Read-only; no target state is changed.",
    runtimeModelBinding: runtimeModelBinding(input.agentId),
    action: {
      actionType: input.actionType,
      actionClass: input.actionClass,
      target: TARGET,
      arguments: {
        schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
        executionBinding: "reviewed_local_process",
        toolId: input.actionType,
        parameters: { exactTarget: TARGET },
      },
      intentSummary: `${input.title} on the exact authorized host`,
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
  };
}

function candidateCatalog(): BuildProviderAdvisoryCatalogInput {
  return {
    planningRequestId: PLANNING_REQUEST_ID,
    contractHash: CONTRACT_HASH,
    policyHash: POLICY_HASH,
    contextPackId: CONTEXT_PACK_ID,
    allowedTargets: [TARGET],
    allowedActionClassIds: [
      "active_host_discovery",
      "cve_intelligence_applicability_validation",
    ],
    prohibitedActionClassIds: [],
    allowedAgentIds: ["ReconScout", "VulnIntel"],
    maximumSteps: 4,
    candidates: [
      {
        publicSummary: {
          phase: "Reachability",
          purpose:
            "Confirm whether the approved environment answers a bounded probe.",
        },
        step: step({
          actionClass: "active_host_discovery",
          actionType: "kali:ping-host-liveness",
          agentId: "ReconScout",
          title: "Host reachability",
        }),
        requiredEvidenceTypeIds: ["asset_discovery_proof"],
      },
      {
        publicSummary: {
          phase: "Applicability review",
          purpose:
            "Compare verified product observations with authoritative advisories.",
        },
        step: step({
          actionClass: "cve_intelligence_applicability_validation",
          actionType: "ti-scale:autonomous-cve-applicability",
          agentId: "VulnIntel",
          title: "CVE applicability",
        }),
        requiredEvidenceTypeIds: [
          "cve_applicability",
          "service_version_fingerprint",
        ],
      },
    ],
  };
}

function binding(): ProviderAdvisoryResolvedPlanningBinding {
  return {
    agentId: ADVISOR_AGENT_ID,
    primaryConfigurationId: ADVISOR_CONFIGURATION_ID,
    providerId: "openrouter",
    modelId: ADVISOR_MODEL,
    modelConfigurationHash: resolveOpenRouterModelConfiguration({
      model: ADVISOR_MODEL,
    }).configurationHash,
    disclosureClass: "sanitized_internal",
    enforcementMode: "advisor_only",
    executionAuthority: "none",
  };
}

function contextItems(): readonly ResearchSourceItem[] {
  return [{
    id: "brain-context-runtime",
    kind: "sanitized_observation",
    classification: "internal",
    disclosureClass: "internal_sanitized",
    content:
      `Raw Brain note for ${TARGET}: Authorization Bearer secret-never-public; prefer a current attributable observation.`,
    verified: true,
  }];
}

function request(): ProviderAdvisoryRuntimeRequest {
  return {
    missionId: MISSION_ID,
    runId: RUN_ID,
    providerTurnId: PROVIDER_TURN_ID,
    signedSelection: PROVIDER_SELECTION,
    resolvedBinding: binding(),
    candidateCatalog: candidateCatalog(),
    createdAt: NOW,
    contextItems: contextItems(),
  };
}

function responseForBody(
  body: string,
  extra: Record<string, unknown> = {},
  returnedModel?: string,
) {
  const outbound = JSON.parse(body) as {
    messages: readonly { readonly role: string; readonly content: string }[];
    model: string;
  };
  const user = outbound.messages.find(({ role }) => role === "user");
  const brief = JSON.parse(user!.content) as {
    readonly catalogHash: string;
    readonly candidates: readonly { readonly candidateId: string }[];
  };
  return new Response(JSON.stringify({
    model: returnedModel ?? outbound.model,
    choices: [{
      finish_reason: "stop",
      message: {
        content: JSON.stringify({
          schemaVersion: PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION,
          catalogHash: brief.catalogHash,
          advisoryOnly: true,
          executionRequested: false,
          orderedCandidateIds: brief.candidates
            .map(({ candidateId }) => candidateId)
            .reverse(),
          rationale:
            "Review the independent applicability candidate before the reachability candidate.",
          ...extra,
        }),
      },
    }],
    usage: {
      prompt_tokens: 100,
      completion_tokens: 30,
      total_tokens: 130,
      cost: 0.002,
    },
  }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function service(
  db: SqliteDatabase,
  fetch: NonNullable<
    ConstructorParameters<typeof OpenRouterPlanningClient>[0]["fetch"]
  >,
) {
  const auditor = new OpenRouterProviderRequestAuditor({
    database: db,
    now: () => new Date(NOW),
    maximumReceiptAgeMs: 60_000,
  });
  const client = new OpenRouterPlanningClient({
    credentialPath: "/not/read/in-tests",
    credentialReader: () => "test-openrouter-key",
    requestAuditor: auditor,
    fetch,
    now: () => new Date(NOW),
  });
  return new ProviderAdvisoryRuntimeService({
    database: db,
    providerClient: client,
  });
}

describe("ProviderAdvisoryRuntimeService", () => {
  test("persists disclosure and exact request bytes before network, then compiles opaque advice locally", async () => {
    const db = database();
    seed(db);
    let capturedBody = "";
    let networkCalls = 0;
    const runtime = service(db, async (_url, init) => {
      networkCalls += 1;
      capturedBody = String(init?.body ?? "");
      const row = db.prepare(`
        SELECT request_body_hash, request_body_bytes, request_authorized_at
        FROM provider_exposure_receipts
      `).get() as {
        request_body_hash: string | null;
        request_body_bytes: number | null;
        request_authorized_at: string | null;
      };
      expect(row.request_authorized_at).toBe(NOW);
      expect(row.request_body_hash).toBe(sha256(capturedBody));
      expect(row.request_body_bytes).toBe(
        Buffer.byteLength(capturedBody, "utf8"),
      );
      return responseForBody(capturedBody);
    });

    const result = await runtime.plan(
      request(),
      new AbortController().signal,
    );

    expect(networkCalls).toBe(1);
    expect(result.status).toBe("planned");
    if (result.status !== "planned") throw new Error("Expected a plan");
    expect(result.localFallbackApplied).toBe(false);
    expect(result.requestBinding.requestBodyHash).toBe(sha256(capturedBody));
    expect(result.receipt.source).toBe("provider_advisory");
    expect(result.plan.steps.map(({ action }) => action.actionType)).toEqual([
      "ti-scale:autonomous-cve-applicability",
      "kali:ping-host-liveness",
    ]);
    expect(result.receipt.evidenceRequirements).toEqual([
      {
        candidateId: result.receipt.orderedCandidateIds[0],
        evidenceTypeIds: [
          "cve_applicability",
          "service_version_fingerprint",
        ],
      },
      {
        candidateId: result.receipt.orderedCandidateIds[1],
        evidenceTypeIds: ["asset_discovery_proof"],
      },
    ]);
    expect(result.advisorBinding).toMatchObject({
      modelId: ADVISOR_MODEL,
      executionAuthority: "none",
    });
    expect(result.executionBindings).toHaveLength(2);
    expect(result.executionBindings.every(({ modelId }) =>
      modelId === "specialist-execution-model")).toBe(true);
    expect(result.plan.steps.every(({ runtimeModelBinding }) =>
      runtimeModelBinding?.modelId !== ADVISOR_MODEL)).toBe(true);

    expect(capturedBody).not.toContain(TARGET);
    expect(capturedBody).not.toContain("kali:ping-host-liveness");
    expect(capturedBody).not.toContain("secret-never-public");
    expect(capturedBody).not.toContain(contextItems()[0]!.content);
    expect(capturedBody).toContain("candidate_");
  });

  test("rejects operational returned-model drift from the fresh readiness identity while retaining billed usage", async () => {
    const db = database();
    seed(db);
    const runtime = service(db, async (_url, init) =>
      responseForBody(
        String(init?.body ?? ""),
        {},
        "openai/gpt-5.2-drifted-backend",
      ));
    const input = request();
    const result = await runtime.plan({
      ...input,
      resolvedBinding: {
        ...input.resolvedBinding,
        attestedReturnedModel: "openai/gpt-5.2-attested-backend",
      },
    }, new AbortController().signal);

    expect(result.status).toBe("safe_stopped");
    if (result.status !== "safe_stopped") throw new Error("Expected safe stop");
    expect(result.safeStop).toMatchObject({
      code: "provider_advisory_result_binding_mismatch",
      category: "provider_refused",
      retryable: false,
      providerUsage: {
        returnedModel: "openai/gpt-5.2-drifted-backend",
        inputTokens: 100,
        outputTokens: 30,
        providerTokens: 130,
        billedCostUsd: 0.002,
        exactTokenUsage: true,
        exactCostUsage: true,
      },
    });
  });

  test("returns typed safe stops without deterministic fallback on outage or provider refusal", async () => {
    const outageDb = database();
    seed(outageDb);
    let outageCalls = 0;
    const outage = service(outageDb, async () => {
      outageCalls += 1;
      throw new TypeError("private network detail must not escape");
    });
    const unavailable = await outage.plan(
      request(),
      new AbortController().signal,
    );
    expect(unavailable).toEqual({
      status: "safe_stopped",
      safeStop: expect.objectContaining({
        transition: "safe_stop",
        category: "provider_unavailable",
        localCandidatesPreserved: true,
        localFallbackApplied: false,
      }),
    });
    expect(JSON.stringify(unavailable)).not.toContain("private network");
    expect(outageCalls).toBe(1);

    const refusalDb = database();
    seed(refusalDb);
    const refusal = service(refusalDb, async () =>
      new Response("{}", {
        status: 400,
        headers: { "content-type": "application/json" },
      }));
    const refused = await refusal.plan(
      request(),
      new AbortController().signal,
    );
    expect(refused).toEqual({
      status: "safe_stopped",
      safeStop: expect.objectContaining({
        category: "provider_refused",
        localFallbackApplied: false,
      }),
    });
  });

  test("rejects signed-route, scope and execution-binding tampering before network contact", async () => {
    const db = database();
    seed(db);
    let networkCalls = 0;
    const runtime = service(db, async (_url, init) => {
      networkCalls += 1;
      return responseForBody(String(init?.body ?? ""));
    });
    const alteredSelection = {
      ...PROVIDER_SELECTION,
      primaryConfigurationId: "configuration-other",
    } as const;
    await expect(runtime.plan({
      ...request(),
      signedSelection: alteredSelection,
    }, new AbortController().signal)).rejects.toMatchObject({
      code: "provider_advisory_resolved_binding_mismatch",
    });

    const outsideScope = candidateCatalog();
    await expect(runtime.plan({
      ...request(),
      candidateCatalog: {
        ...outsideScope,
        allowedTargets: ["10.0.0.99"],
        candidates: outsideScope.candidates.map((candidate) => ({
          ...candidate,
          step: {
            ...candidate.step,
            action: {
              ...candidate.step.action,
              target: "10.0.0.99",
            },
          },
        })),
      },
    }, new AbortController().signal)).rejects.toMatchObject({
      code: "provider_advisory_target_scope_mismatch",
    });

    const missingBinding = candidateCatalog();
    await expect(runtime.plan({
      ...request(),
      candidateCatalog: {
        ...missingBinding,
        candidates: missingBinding.candidates.map((candidate) => ({
          ...candidate,
          step: {
            ...candidate.step,
            runtimeModelBinding: undefined,
          },
        })),
      },
    }, new AbortController().signal)).rejects.toMatchObject({
      code: "provider_advisory_execution_binding_missing",
    });
    expect(networkCalls).toBe(0);
    expect(db.prepare(
      "SELECT COUNT(*) AS count FROM provider_exposure_receipts",
    ).get()).toEqual({ count: 0 });
  });

  test("keeps deterministic receipt persistence idempotent but rejects request replay before a second fetch", async () => {
    const db = database();
    seed(db);
    let networkCalls = 0;
    const runtime = service(db, async (_url, init) => {
      networkCalls += 1;
      return responseForBody(String(init?.body ?? ""));
    });
    const first = await runtime.plan(
      request(),
      new AbortController().signal,
    );
    expect(first.status).toBe("planned");
    const second = await runtime.plan(
      request(),
      new AbortController().signal,
    );
    expect(second).toEqual({
      status: "safe_stopped",
      safeStop: expect.objectContaining({
        category: "audit_unavailable",
        retryable: false,
        localFallbackApplied: false,
      }),
    });
    expect(networkCalls).toBe(1);
    expect(db.prepare(
      "SELECT COUNT(*) AS count FROM provider_exposure_receipts",
    ).get()).toEqual({ count: 1 });
  });

  test("rejects provider attempts to add executable fields and returns no partial plan", async () => {
    const db = database();
    seed(db);
    const runtime = service(db, async (_url, init) =>
      responseForBody(String(init?.body ?? ""), {
        toolArguments: { command: "id" },
      }));
    const outcome = await runtime.plan(
      request(),
      new AbortController().signal,
    );
    expect(outcome).toEqual({
      status: "safe_stopped",
      safeStop: expect.objectContaining({
        category: "provider_refused",
        retryable: false,
        localFallbackApplied: false,
        providerUsage: {
          providerId: "openrouter",
          requestedModel: ADVISOR_MODEL,
          returnedModel: ADVISOR_MODEL,
          inputTokens: 100,
          outputTokens: 30,
          totalTokens: 130,
          providerTokens: 130,
          billedCostUsd: 0.002,
          estimatedCost: 0.002,
          exactTokenUsage: true,
          exactCostUsage: true,
        },
      }),
    });
    expect("plan" in outcome).toBe(false);
  });

  test("treats a missing exact-request identity as a nonretryable audit safe stop", async () => {
    const db = database();
    seed(db);
    const runtime = new ProviderAdvisoryRuntimeService({
      database: db,
      providerClient: {
        async callStructuredJson(input) {
          const user = input.messages.find(({ role }) => role === "user");
          const brief = JSON.parse(user!.content) as {
            readonly catalogHash: string;
            readonly candidates: readonly {
              readonly candidateId: string;
            }[];
          };
          const value = input.response.validate({
            schemaVersion: PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION,
            catalogHash: brief.catalogHash,
            advisoryOnly: true,
            executionRequested: false,
            orderedCandidateIds: brief.candidates.map(
              ({ candidateId }) => candidateId,
            ),
            rationale:
              "Keep the locally materialized dependency-safe order.",
          });
          return {
            value,
            providerId: "openrouter",
            requestedModel: input.model,
            returnedModel: input.model,
            usage: {
              inputTokens: 10,
              outputTokens: 5,
              providerTokens: 15,
              billedCostUsd: 0.0002,
              exactTokenUsage: true,
              exactCostUsage: true,
            },
            exposure: input.exposure,
          };
        },
      },
    });

    const outcome = await runtime.plan(
      request(),
      new AbortController().signal,
    );
    expect(outcome).toEqual({
      status: "safe_stopped",
      safeStop: expect.objectContaining({
        code: "provider_advisory_request_binding_missing",
        category: "audit_unavailable",
        retryable: false,
        localFallbackApplied: false,
      }),
    });
  });
});

describe("SignedAutonomousPlanningRoutePort", () => {
  test("selects local and provider planning per call only when each supplied selection matches its confirmed contract", async () => {
    const localDb = database();
    seed(localDb, LOCAL_SELECTION);
    let localCalls = 0;
    let providerCalls = 0;
    const localProviderStub = {
      route: "provider_advisory" as const,
      executionAuthority: "none" as const,
      async plan() {
        providerCalls += 1;
        throw new Error("Provider route must not be called");
      },
    };
    const localRouter = new SignedAutonomousPlanningRoutePort({
      database: localDb,
      local: {
        route: "local_deterministic",
        async plan(value: { readonly marker: string }) {
          localCalls += 1;
          return { accepted: value.marker };
        },
      },
      provider: localProviderStub,
    });
    const local = await localRouter.plan({
      route: "local_deterministic",
      missionId: MISSION_ID,
      runId: RUN_ID,
      signedSelection: LOCAL_SELECTION,
      localInput: { marker: "local-exact" },
    }, new AbortController().signal);
    expect(local).toEqual({
      status: "planned",
      route: "local_deterministic",
      result: { accepted: "local-exact" },
    });
    expect(localCalls).toBe(1);
    expect(providerCalls).toBe(0);

    await expect(localRouter.plan({
      route: "provider_advisory",
      missionId: MISSION_ID,
      runId: RUN_ID,
      signedSelection: PROVIDER_SELECTION,
      providerInput: {
        providerTurnId: PROVIDER_TURN_ID,
        resolvedBinding: binding(),
        candidateCatalog: candidateCatalog(),
        createdAt: NOW,
      },
    }, new AbortController().signal)).rejects.toBeInstanceOf(
      ProviderAdvisoryPlanningError,
    );
    expect(providerCalls).toBe(0);

    const providerDb = database();
    seed(providerDb);
    const providerRuntime = service(providerDb, async (_url, init) => {
      providerCalls += 1;
      return responseForBody(String(init?.body ?? ""));
    });
    const providerRouter = new SignedAutonomousPlanningRoutePort({
      database: providerDb,
      local: {
        route: "local_deterministic",
        async plan() {
          localCalls += 1;
          return { accepted: "unexpected" };
        },
      },
      provider: providerRuntime,
    });
    const provider = await providerRouter.plan({
      route: "provider_advisory",
      missionId: MISSION_ID,
      runId: RUN_ID,
      signedSelection: PROVIDER_SELECTION,
      providerInput: {
        providerTurnId: PROVIDER_TURN_ID,
        resolvedBinding: binding(),
        candidateCatalog: candidateCatalog(),
        createdAt: NOW,
      },
    }, new AbortController().signal);
    expect(provider.status).toBe("planned");
    if (provider.status !== "planned") {
      throw new Error("Expected provider plan");
    }
    expect(provider.route).toBe("provider_advisory");
    expect(providerCalls).toBe(1);
    expect(localCalls).toBe(1);
  });
});

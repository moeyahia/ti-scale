import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  AgentRuntimeBindingError,
  AgentRuntimeBindingService,
} from "../index";

const NOW = "2026-07-23T17:00:00.000Z";
const MISSION_ID = "mission-agent-runtime";
const RUN_ID = "run-agent-runtime";
const PLAN_ID = "plan-agent-runtime";
const STEP_ID = "step-agent-runtime";

type ConfigurationOverrides = Readonly<{
  compatibleAgentIds?: readonly string[];
  enforcementMode?: "enforced" | "observe_only" | "advisory_only" | "unavailable";
  authState?: "healthy" | "missing" | "expired" | "degraded" | "unknown";
  healthState?: "healthy" | "degraded" | "offline" | "unknown";
  disclosureClass?: "public_only" | "sanitized_internal" | "local_only" | "unavailable";
  catalogRetrievedAt?: string;
}>;

describe("AgentRuntimeBindingService", () => {
  let database: SqliteDatabase;
  let service: AgentRuntimeBindingService;

  beforeEach(() => {
    database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    insertAgent("ReconScout");
    insertAgent("WebBreaker");
    insertAgent("runtime:internal-recon");
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, created_by, created_at, updated_at
      ) VALUES (?, 'Runtime binding mission', 'Assess the authorized lab',
        'guided', 'operator', ?, ?)
    `).run(MISSION_ID, NOW, NOW);
    database.prepare(`
      INSERT INTO mission_contracts (
        id, mission_id, version, state, contract_hash,
        authorization_json, action_policy_json, budgets_json,
        safe_stop_json, deliverables_json, memory_scopes_json,
        confirmed_by, confirmed_at, created_at
      ) VALUES (
        'contract-agent-runtime', ?, 1, 'confirmed', ?, '{}',
        '{"specialistAgentIds":[],"agentModelAssignments":[]}', '{}',
        '{}', '[]', '[]', 'operator', ?, ?
      )
    `).run(MISSION_ID, "c".repeat(64), NOW, NOW);
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, contract_id,
        contract_version_bound, contract_hash_bound, created_at, updated_at
      ) VALUES (?, ?, 'guided', 'running', 'contract-agent-runtime',
        1, ?, ?, ?)
    `).run(RUN_ID, MISSION_ID, "c".repeat(64), NOW, NOW);
    database.prepare(`
      INSERT INTO plans (
        id, run_id, version, status, strategy_summary, plan_hash,
        content_hash, content_hash_version, created_by, created_at
      ) VALUES (?, ?, 1, 'active', 'Test runtime binding', ?, ?, 1,
        'operator', ?)
    `).run(PLAN_ID, RUN_ID, "a".repeat(64), "b".repeat(64), NOW);
    insertStep({
      id: STEP_ID,
      assignedAgentId: "ReconScout",
      actionClassId: "port_service_enumeration",
    });
    service = new AgentRuntimeBindingService(database, undefined, {
      clock: () => new Date(NOW),
    });
  });

  afterEach(() => database.close());

  function insertAgent(id: string): void {
    database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, version, created_at, updated_at
      ) VALUES (?, 'test role', ?, 'available', 'test-v1', ?, ?)
    `).run(id, id, NOW, NOW);
  }

  function insertStep(input: Readonly<{
    id: string;
    assignedAgentId?: string | null;
    actionClassId?: string | null;
    ordinal?: number;
  }>): void {
    database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        action_class, assigned_agent_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'reconnaissance', 'Inspect the target',
        'Create attributable observations', 'ready', ?, ?, ?, ?)
    `).run(
      input.id,
      PLAN_ID,
      RUN_ID,
      input.ordinal ?? 0,
      input.actionClassId ?? null,
      input.assignedAgentId ?? null,
      NOW,
      NOW,
    );
  }

  function insertConfiguration(
    id: string,
    overrides: ConfigurationOverrides = {},
  ): void {
    database.prepare(`
      INSERT INTO model_configurations (
        id, provider_id, model_id, returned_model_id, reasoning_effort,
        context_policy_json, capabilities_json, context_limit,
        cost_class, latency_class, disclosure_class, enforcement_mode,
        auth_state, health_state, catalog_source, catalog_retrieved_at,
        configuration_source, prompt_template_hash,
        created_at, updated_at, version
      ) VALUES (?, ?, ?, NULL, 'high', '{}', ?, 128000,
        'standard', 'standard', ?, ?, ?, ?, 'test-live-catalog', ?,
        'manual', NULL, ?, ?, 1)
    `).run(
      id,
      `provider-${id}`,
      `model-${id}`,
      JSON.stringify({
        displayName: id,
        compatibleAgentIds: overrides.compatibleAgentIds ?? ["ReconScout"],
        toolCalling: true,
        structuredOutput: true,
      }),
      overrides.disclosureClass ?? "sanitized_internal",
      overrides.enforcementMode ?? "enforced",
      overrides.authState ?? "healthy",
      overrides.healthState ?? "healthy",
      overrides.catalogRetrievedAt ?? NOW,
      NOW,
      NOW,
    );
  }

  function insertAssignment(input: Readonly<{
    id: string;
    agentId?: string;
    missionId?: string | null;
    runId?: string | null;
    stepId?: string | null;
    primaryConfigurationId: string;
    fallbackConfigurationId?: string | null;
    pinned?: boolean;
    purpose?: "execution" | "planning";
  }>): void {
    database.prepare(`
      INSERT INTO agent_model_assignments (
        id, agent_id, mission_id, run_id, step_id,
        assignment_purpose,
        primary_configuration_id, fallback_configuration_id,
        inheritance_level, pinned, resolution_reason, resolved_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'agent', ?, ?, ?, ?)
    `).run(
      input.id,
      input.agentId ?? "ReconScout",
      input.missionId === undefined ? MISSION_ID : input.missionId,
      input.runId === undefined ? RUN_ID : input.runId,
      input.stepId ?? null,
      input.purpose ?? "execution",
      input.primaryConfigurationId,
      input.fallbackConfigurationId ?? null,
      input.pinned === false ? 0 : 1,
      `Pinned test assignment ${input.id}`,
      NOW,
      NOW,
    );
  }

  function expectBindingError(
    operation: () => unknown,
    code: AgentRuntimeBindingError["code"],
  ): AgentRuntimeBindingError {
    try {
      operation();
    } catch (error) {
      expect(error).toBeInstanceOf(AgentRuntimeBindingError);
      expect((error as AgentRuntimeBindingError).code).toBe(code);
      return error as AgentRuntimeBindingError;
    }
    throw new Error(`Expected AgentRuntimeBindingError ${code}`);
  }

  function bindAutonomousContract(input: Readonly<{
    primaryConfigurationId: string;
    fallbackConfigurationId?: string | null;
  }>): void {
    database.prepare(`
      UPDATE mission_contracts
      SET action_policy_json = ?
      WHERE id = 'contract-agent-runtime'
    `).run(
      JSON.stringify({
        specialistAgentIds: ["ReconScout"],
        agentModelAssignments: [{
          agentId: "ReconScout",
          primaryConfigurationId: input.primaryConfigurationId,
          fallbackConfigurationId: input.fallbackConfigurationId ?? null,
          source: "operator_override",
        }],
      }),
    );
    database.prepare(`
      UPDATE missions SET journey = 'autonomous' WHERE id = ?
    `).run(MISSION_ID);
    database.prepare(`
      UPDATE runs SET journey = 'autonomous' WHERE id = ?
    `).run(RUN_ID);
  }

  test("prefers the exact assigned product agent and exact step pin, returning a deeply immutable binding", () => {
    database.prepare(`
      UPDATE plan_steps
      SET action_class = 'web_crawling_page_capture'
      WHERE id = ?
    `).run(STEP_ID);
    insertConfiguration("config-primary");
    insertConfiguration("config-fallback");
    insertAssignment({
      id: "assignment-run",
      primaryConfigurationId: "config-fallback",
    });
    insertAssignment({
      id: "assignment-step",
      stepId: STEP_ID,
      primaryConfigurationId: "config-primary",
      fallbackConfigurationId: "config-fallback",
    });

    const binding = service.resolve({
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: STEP_ID,
    });

    expect(binding).toMatchObject({
      schemaVersion: "ti-scale.agent-runtime-binding.v1",
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: STEP_ID,
      representedActionClassId: "web_crawling_page_capture",
      productAgentId: "ReconScout",
      productAgentResolutionSource: "assigned_product_agent",
      modelAssignmentId: "assignment-step",
      modelAssignmentScope: "step",
      primaryConfigurationId: "config-primary",
      fallbackConfigurationId: "config-fallback",
    });
    expect(binding.primaryConfiguration.id).toBe("config-primary");
    expect(binding.fallbackConfiguration?.id).toBe("config-fallback");
    expect(Object.isFrozen(binding)).toBeTrue();
    expect(Object.isFrozen(binding.primaryConfiguration)).toBeTrue();
    expect(Object.isFrozen(binding.primaryConfiguration.capabilities)).toBeTrue();
    expect(Object.isFrozen(
      binding.primaryConfiguration.capabilities.compatibleAgentIds,
    )).toBeTrue();
  });

  test("maps an internal adapter assignment through the action-class registry and uses a run pin", () => {
    database.prepare(`
      UPDATE plan_steps
      SET assigned_agent_id = 'runtime:internal-recon',
          action_class = 'port_service_enumeration'
      WHERE id = ?
    `).run(STEP_ID);
    insertConfiguration("config-run");
    insertAssignment({
      id: "assignment-run",
      primaryConfigurationId: "config-run",
    });

    expect(service.resolve({
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: STEP_ID,
    })).toMatchObject({
      productAgentId: "ReconScout",
      productAgentResolutionSource: "action_class_registry",
      modelAssignmentId: "assignment-run",
      modelAssignmentScope: "run",
    });
  });

  test("ignores an unpinned step candidate and falls back to the pinned run assignment", () => {
    insertConfiguration("config-run");
    insertConfiguration("config-unpinned");
    insertAssignment({
      id: "assignment-unpinned-step",
      stepId: STEP_ID,
      primaryConfigurationId: "config-unpinned",
      pinned: false,
    });
    insertAssignment({
      id: "assignment-run",
      primaryConfigurationId: "config-run",
    });

    expect(service.resolve({
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: STEP_ID,
    }).modelAssignmentId).toBe("assignment-run");
  });

  test("never treats a planning-only pin as execution authority", () => {
    insertConfiguration("config-planning");
    insertAssignment({
      id: "assignment-planning-only",
      primaryConfigurationId: "config-planning",
      purpose: "planning",
    });

    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_assignment_missing",
    );
    expectBindingError(
      () => service.resolveRun({
        missionId: MISSION_ID,
        runId: RUN_ID,
        agentId: "ReconScout",
      }),
      "agent_runtime_binding_model_assignment_missing",
    );
  });

  test("ignores planning pins at step and run scope when execution authority exists", () => {
    insertConfiguration("config-planning");
    insertConfiguration("config-execution");
    insertAssignment({
      id: "assignment-planning-step",
      stepId: STEP_ID,
      primaryConfigurationId: "config-planning",
      purpose: "planning",
    });
    insertAssignment({
      id: "assignment-planning-run",
      primaryConfigurationId: "config-planning",
      purpose: "planning",
    });
    insertAssignment({
      id: "assignment-execution-run",
      primaryConfigurationId: "config-execution",
    });

    expect(service.resolve({
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: STEP_ID,
    })).toMatchObject({
      modelAssignmentId: "assignment-execution-run",
      modelAssignmentScope: "run",
      primaryConfigurationId: "config-execution",
    });
    expect(service.resolveRun({
      missionId: MISSION_ID,
      runId: RUN_ID,
      agentId: "ReconScout",
    })).toMatchObject({
      modelAssignmentId: "assignment-execution-run",
      primaryConfigurationId: "config-execution",
    });
  });

  test("fails closed for blank IDs, a missing step, and mismatched mission or run scope", () => {
    expectBindingError(
      () => service.resolve({
        missionId: " ",
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_invalid_input",
    );
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: "step-missing",
      }),
      "agent_runtime_binding_step_not_found",
    );
    expectBindingError(
      () => service.resolve({
        missionId: "mission-other",
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_scope_mismatch",
    );
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: "run-other",
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_scope_mismatch",
    );
  });

  test("fails closed when neither assignment nor action class identifies a product agent", () => {
    database.prepare(`
      UPDATE plan_steps
      SET assigned_agent_id = 'runtime:internal-recon', action_class = NULL
      WHERE id = ?
    `).run(STEP_ID);
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_product_agent_missing",
    );

    database.prepare(`
      UPDATE plan_steps SET action_class = 'unregistered-action' WHERE id = ?
    `).run(STEP_ID);
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_product_agent_missing",
    );
  });

  test("does not silently fall back when a step pin belongs to another product agent", () => {
    insertConfiguration("config-recon");
    insertConfiguration("config-web", { compatibleAgentIds: ["WebBreaker"] });
    insertAssignment({
      id: "assignment-run",
      primaryConfigurationId: "config-recon",
    });
    insertAssignment({
      id: "assignment-wrong-step",
      agentId: "WebBreaker",
      stepId: STEP_ID,
      primaryConfigurationId: "config-web",
    });

    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_assignment_scope_mismatch",
    );
  });

  test("rejects multiple product-agent pins on one step instead of selecting by insertion order", () => {
    insertConfiguration("config-one");
    insertConfiguration("config-two", { compatibleAgentIds: ["WebBreaker"] });
    insertAssignment({
      id: "assignment-step-one",
      stepId: STEP_ID,
      primaryConfigurationId: "config-one",
    });
    insertAssignment({
      id: "assignment-step-two",
      agentId: "WebBreaker",
      stepId: STEP_ID,
      primaryConfigurationId: "config-two",
    });
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_assignment_ambiguous",
    );
  });

  test("defensively rejects duplicate run pins in a pre-unique-index database", () => {
    insertConfiguration("config-one");
    insertConfiguration("config-two");
    database.prepare(
      "DROP INDEX IF EXISTS idx_agent_model_assignments_pinned_scope",
    ).run();
    insertAssignment({
      id: "assignment-run-one",
      primaryConfigurationId: "config-one",
    });
    insertAssignment({
      id: "assignment-run-two",
      primaryConfigurationId: "config-two",
    });
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_assignment_ambiguous",
    );
  });

  test("requires an already-pinned step or run assignment and never creates one", () => {
    insertConfiguration("config-unpinned");
    insertAssignment({
      id: "assignment-unpinned",
      primaryConfigurationId: "config-unpinned",
      pinned: false,
    });
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_assignment_missing",
    );
    expect(database.prepare(`
      SELECT count(*) AS count
      FROM agent_model_assignments
      WHERE pinned = 1
    `).get()).toEqual({ count: 0 });
  });

  test("rejects a run assignment whose stored mission lineage does not match", () => {
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, created_by, created_at, updated_at
      ) VALUES ('mission-other', 'Other mission', 'Other authorized scope',
        'autonomous', 'operator', ?, ?)
    `).run(NOW, NOW);
    insertConfiguration("config-primary");
    insertAssignment({
      id: "assignment-wrong-mission",
      missionId: "mission-other",
      primaryConfigurationId: "config-primary",
    });
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_assignment_scope_mismatch",
    );
  });

  test.each([
    ["unconfigured auth", { authState: "missing" as const }],
    ["degraded health", { healthState: "degraded" as const }],
    ["unavailable enforcement", { enforcementMode: "unavailable" as const }],
    ["unavailable disclosure", { disclosureClass: "unavailable" as const }],
    ["invalid catalog timestamp", { catalogRetrievedAt: "not-a-time" }],
  ])("rejects an unselectable primary configuration: %s", (_label, overrides) => {
    insertConfiguration("config-primary", overrides);
    insertAssignment({
      id: "assignment-run",
      primaryConfigurationId: "config-primary",
    });
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_configuration_unavailable",
    );
  });

  test("rejects primary and fallback configurations not explicitly compatible with the resolved agent", () => {
    insertConfiguration("config-primary", {
      compatibleAgentIds: ["WebBreaker"],
    });
    insertAssignment({
      id: "assignment-primary-incompatible",
      primaryConfigurationId: "config-primary",
    });
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_configuration_incompatible",
    );

    database.prepare("DELETE FROM agent_model_assignments").run();
    insertConfiguration("config-compatible");
    insertConfiguration("config-fallback-incompatible", {
      compatibleAgentIds: ["WebBreaker"],
    });
    insertAssignment({
      id: "assignment-fallback-incompatible",
      primaryConfigurationId: "config-compatible",
      fallbackConfigurationId: "config-fallback-incompatible",
    });
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_configuration_incompatible",
    );
  });

  test("rejects an unavailable fallback even when the primary configuration is valid", () => {
    insertConfiguration("config-primary");
    insertConfiguration("config-fallback", { healthState: "offline" });
    insertAssignment({
      id: "assignment-run",
      primaryConfigurationId: "config-primary",
      fallbackConfigurationId: "config-fallback",
    });
    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_model_configuration_unavailable",
    );
  });

  test.each([
    ["stale", new Date(Date.parse(NOW) - 16 * 60_000).toISOString()],
    ["future-dated", new Date(Date.parse(NOW) + 10_000).toISOString()],
  ])("enforces the default %s catalog-time boundary without constructor options", (
    _label,
    observedAt,
  ) => {
    insertConfiguration("config-default-time-invalid", {
      catalogRetrievedAt: observedAt,
    });
    insertAssignment({
      id: "assignment-default-time-invalid",
      primaryConfigurationId: "config-default-time-invalid",
    });
    const defaultPolicyService = new AgentRuntimeBindingService(database);

    expectBindingError(
      () => defaultPolicyService.resolveRun({
        missionId: MISSION_ID,
        runId: RUN_ID,
        agentId: "ReconScout",
      }),
      "agent_runtime_binding_model_configuration_unavailable",
    );
  });

  test("retains a fresh-at-launch signed pin after more than the catalog freshness window", () => {
    insertConfiguration("config-long-running");
    insertAssignment({
      id: "assignment-long-running",
      primaryConfigurationId: "config-long-running",
    });
    bindAutonomousContract({
      primaryConfigurationId: "config-long-running",
    });
    service = new AgentRuntimeBindingService(database, undefined, {
      clock: () => new Date(Date.parse(NOW) + 30 * 60_000),
    });

    expect(service.resolveRun({
      missionId: MISSION_ID,
      runId: RUN_ID,
      agentId: "ReconScout",
    })).toMatchObject({
      modelAssignmentId: "assignment-long-running",
      primaryConfigurationId: "config-long-running",
    });
  });

  test("resolves only the exact run pin named by the confirmed Autonomous contract", () => {
    insertConfiguration("config-signed");
    insertAssignment({
      id: "assignment-signed",
      primaryConfigurationId: "config-signed",
    });
    bindAutonomousContract({ primaryConfigurationId: "config-signed" });
    service = new AgentRuntimeBindingService(database, undefined, {
      clock: () => new Date(NOW),
    });

    expect(service.resolveRun({
      missionId: MISSION_ID,
      runId: RUN_ID,
      agentId: "ReconScout",
    })).toMatchObject({
      modelAssignmentId: "assignment-signed",
      modelAssignmentScope: "run",
      primaryConfigurationId: "config-signed",
      productAgentId: "ReconScout",
    });
  });

  test("fails closed when the run pin drifts from the signed Autonomous configuration", () => {
    insertConfiguration("config-signed");
    insertConfiguration("config-drifted");
    insertAssignment({
      id: "assignment-drifted",
      primaryConfigurationId: "config-drifted",
    });
    bindAutonomousContract({ primaryConfigurationId: "config-signed" });
    service = new AgentRuntimeBindingService(database, undefined, {
      clock: () => new Date(NOW),
    });

    expectBindingError(
      () => service.resolveRun({
        missionId: MISSION_ID,
        runId: RUN_ID,
        agentId: "ReconScout",
      }),
      "agent_runtime_binding_signed_assignment_mismatch",
    );
  });

  test("does not let an Autonomous step pin replace the signed run pin", () => {
    insertConfiguration("config-signed");
    insertAssignment({
      id: "assignment-run",
      primaryConfigurationId: "config-signed",
    });
    insertAssignment({
      id: "assignment-step",
      stepId: STEP_ID,
      primaryConfigurationId: "config-signed",
    });
    bindAutonomousContract({ primaryConfigurationId: "config-signed" });
    service = new AgentRuntimeBindingService(database, undefined, {
      clock: () => new Date(NOW),
    });

    expectBindingError(
      () => service.resolve({
        missionId: MISSION_ID,
        runId: RUN_ID,
        stepId: STEP_ID,
      }),
      "agent_runtime_binding_signed_assignment_mismatch",
    );
  });

  test.each([
    ["stale", "2026-07-23T16:44:59.999Z"],
    ["future-dated", "2026-07-23T17:00:05.001Z"],
  ])("fails closed for a %s signed Autonomous catalog snapshot", (_label, observedAt) => {
    insertConfiguration("config-time-invalid", {
      catalogRetrievedAt: observedAt,
    });
    insertAssignment({
      id: "assignment-time-invalid",
      primaryConfigurationId: "config-time-invalid",
    });
    bindAutonomousContract({
      primaryConfigurationId: "config-time-invalid",
    });
    service = new AgentRuntimeBindingService(database, undefined, {
      clock: () => new Date(NOW),
    });

    expectBindingError(
      () => service.resolveRun({
        missionId: MISSION_ID,
        runId: RUN_ID,
        agentId: "ReconScout",
      }),
      "agent_runtime_binding_model_configuration_unavailable",
    );
  });
});

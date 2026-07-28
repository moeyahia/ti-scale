import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  listAppliedMigrations,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  autonomousActivationEvidencePolicyHash,
  AutonomousActivationReceiptIntegrityError,
  AutonomousActivationReceiptRepository,
  AutonomousActivationReceiptVerifier,
  type AutonomousActivationRouteInput,
  type IssueAutonomousActivationReceiptInput,
} from "../index";
import type { RuntimeSourceManifests } from "../../domain";
import {
  ModelConfigurationRepository,
  ModelConfigurationService,
  type AutonomousPlanningSelection,
} from "../../model-config";

const NOW = "2026-07-28T12:00:00.000Z";
const EXPIRES_AT = "2026-07-28T14:00:00.000Z";
const ROUTE_EXPIRES_AT = "2026-07-28T15:00:00.000Z";
const MISSION_ID = "mission-activation";
const RUN_ID = "run-activation";
const CONTRACT_ID = "contract-activation";
const CONTEXT_PACK_ID = "context-pack-activation";
const CONTRACT_HASH = "a".repeat(64);
const RUNTIME_GENERATION_HASH = "b".repeat(64);
const ACTION_CLASSES = [
  "active_host_discovery",
  "port_service_enumeration",
] as const;
const EVIDENCE_REQUIREMENTS = [
  "host_asset_discovery_proof",
  "port_service_scan_result",
] as const;
const PROVIDER_PLANNING_SELECTION = {
  route: "provider_advisory",
  agentId: "VulnIntel",
  primaryConfigurationId: "configuration-vulnintel-planning",
  fallbackConfigurationId: null,
  enforcementMode: "advisor_only",
  disclosureClass: "sanitized_internal",
  executionAuthority: "none",
} as const satisfies AutonomousPlanningSelection;
const LOCAL_PLANNING_SELECTION = {
  route: "local_deterministic",
  plannerId: "ti-scale.local-autonomous-contract-planner.v1",
  enforcementMode: "local_policy",
  disclosureClass: "local_only",
  executionAuthority: "none",
} as const satisfies AutonomousPlanningSelection;

let database: SqliteDatabase;

afterEach(() => {
  database?.close();
});

beforeEach(() => {
  database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seedActivationBoundary(database);
});

function hash(character: string): string {
  return character.repeat(64);
}

function setContractPlanningSelection(
  target: SqliteDatabase,
  selection: AutonomousPlanningSelection,
): void {
  const row = target.prepare(`
    SELECT action_policy_json FROM mission_contracts WHERE id = ?
  `).get(CONTRACT_ID) as { readonly action_policy_json: string };
  const policy = JSON.parse(row.action_policy_json) as Record<string, unknown>;
  target.prepare(`
    UPDATE mission_contracts SET action_policy_json = ? WHERE id = ?
  `).run(JSON.stringify({ ...policy, planningSelection: selection }), CONTRACT_ID);
}

function seedActivationBoundary(target: SqliteDatabase): void {
  target.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, authorization_status, created_by,
      created_at, updated_at
    ) VALUES (?, 'Activation receipt mission', 'Assess the authorized lab',
      'autonomous', 'verified', 'operator', ?, ?)
  `).run(MISSION_ID, NOW, NOW);
  target.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{}', '{}', '[]', '[]',
      'operator', ?, ?)
  `).run(
    CONTRACT_ID,
    MISSION_ID,
    CONTRACT_HASH,
    JSON.stringify({
      allowedActionClasses: ACTION_CLASSES,
      prohibitedActionClasses: [],
      evidenceRequirements: EVIDENCE_REQUIREMENTS,
      planningSelection: PROVIDER_PLANNING_SELECTION,
    }),
    NOW,
    NOW,
  );
  target.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, contract_version_bound,
      contract_hash_bound, created_at, updated_at
    ) VALUES (?, ?, 'autonomous', 'planning', ?, 1, ?, ?, ?)
  `).run(RUN_ID, MISSION_ID, CONTRACT_ID, CONTRACT_HASH, NOW, NOW);
  for (const [agentId, displayName] of [
    ["VulnIntel", "Vulnerability Intelligence"],
    ["ReconScout", "Recon Scout"],
    ["NetworkMapper", "Network Mapper"],
  ] as const) {
    target.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, version, created_at, updated_at
      ) VALUES (?, 'reconnaissance', ?, 'available', '1.0.0', ?, ?)
    `).run(agentId, displayName, NOW, NOW);
  }
  for (const configuration of [
    { id: "configuration-recon-execution", mode: "enforced" },
    { id: "configuration-network-execution", mode: "enforced" },
    { id: "configuration-vulnintel-planning", mode: "advisory_only" },
    { id: "configuration-drift", mode: "enforced" },
  ] as const) {
    target.prepare(`
      INSERT INTO model_configurations (
        id, provider_id, model_id, context_policy_json, capabilities_json,
        context_limit, cost_class, latency_class, disclosure_class,
        enforcement_mode, auth_state, health_state, catalog_source,
        catalog_retrieved_at, configuration_source, created_at, updated_at,
        version
      ) VALUES (?, 'test-provider', ?, '{}', ?, 32768, 'standard',
        'standard', 'sanitized_internal', ?, 'healthy', 'healthy',
        'test-catalog', ?, 'manual', ?, ?, 1)
    `).run(
      configuration.id,
      configuration.id,
      JSON.stringify({ displayName: configuration.id }),
      configuration.mode,
      NOW,
      NOW,
      NOW,
    );
  }
  for (const assignment of [
    {
      id: "assignment-recon-execution",
      agentId: "ReconScout",
      purpose: "execution",
      configurationId: "configuration-recon-execution",
    },
    {
      id: "assignment-vulnintel-planning",
      agentId: "VulnIntel",
      purpose: "planning",
      configurationId: "configuration-vulnintel-planning",
    },
    {
      id: "assignment-network-execution",
      agentId: "NetworkMapper",
      purpose: "execution",
      configurationId: "configuration-network-execution",
    },
  ] as const) {
    target.prepare(`
      INSERT INTO agent_model_assignments (
        id, agent_id, mission_id, run_id, step_id, assignment_purpose,
        primary_configuration_id, fallback_configuration_id,
        inheritance_level, pinned, resolution_reason, resolved_at, created_at
      ) VALUES (?, ?, ?, ?, NULL, ?, ?, NULL, 'run', 1,
        'Exact activation test pin', ?, ?)
    `).run(
      assignment.id,
      assignment.agentId,
      MISSION_ID,
      RUN_ID,
      assignment.purpose,
      assignment.configurationId,
      NOW,
      NOW,
    );
  }
  target.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json, created_by,
      created_at
    ) VALUES (?, ?, ?, 'autonomous', 'intake',
      'Autonomous activation context', '{}', 2048, '{}', 'system', ?)
  `).run(CONTEXT_PACK_ID, MISSION_ID, RUN_ID, NOW);
  target.prepare(`
    INSERT INTO mcp_servers (
      id, name, transport, status, capabilities_json, policy_json,
      created_at, updated_at
    ) VALUES ('mcp-network', 'Network MCP', 'stdio', 'healthy', '[]', '{}',
      ?, ?)
  `).run(NOW, NOW);
}

function routes(): AutonomousActivationRouteInput[] {
  return [
    {
      actionClassId: "port_service_enumeration",
      agentId: "NetworkMapper",
      executionModelAssignmentId: "assignment-network-execution",
      toolId: "network-scan",
      toolBindingKind: "mcp",
      mcpServerId: "mcp-network",
      toolActivationReceiptId: "tool-receipt-network",
      toolActivationReceiptHash: hash("c"),
      toolManifestHash: hash("d"),
      evidenceTypeIds: ["service_version", "port_scan"],
      evidenceProducerIds: ["producer-network-normalizer"],
      routeExpiresAt: ROUTE_EXPIRES_AT,
    },
    {
      actionClassId: "active_host_discovery",
      agentId: "ReconScout",
      executionModelAssignmentId: "assignment-recon-execution",
      toolId: "local-host-discovery",
      toolBindingKind: "local",
      mcpServerId: null,
      toolActivationReceiptId: "tool-receipt-host",
      toolActivationReceiptHash: hash("e"),
      toolManifestHash: hash("f"),
      evidenceTypeIds: ["host_liveness"],
      evidenceProducerIds: ["producer-host-normalizer"],
      routeExpiresAt: ROUTE_EXPIRES_AT,
    },
  ];
}

function productionConfigurationManifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [],
    mcpServers: [],
    agents: [
      {
        id: "VulnIntel",
        label: "VulnIntel",
        available: true,
        capabilityIds: [],
        actionClassIds: [],
        toolIds: [],
        modelRefs: [{ providerId: "provider-real", modelId: "advisor" }],
      },
      ...(["ReconScout"] as const).map((id) => ({
        id,
        label: id,
        available: true,
        capabilityIds: [],
        actionClassIds: [...ACTION_CLASSES],
        toolIds: [],
        modelRefs: [{ providerId: "provider-real", modelId: "executor" }],
      })),
    ],
    providers: [{
      id: "provider-real",
      authenticated: true,
      healthy: true,
      catalogObservedAt: NOW,
      models: [
        {
          id: "advisor",
          displayName: "Production advisory planner",
          toolCalling: false,
          structuredOutput: true,
          enforcement: "advisor_only",
          compatibleActionClassIds: [],
          disclosureClasses: ["sanitized_internal"],
        },
        {
          id: "executor",
          displayName: "Production enforced executor",
          toolCalling: true,
          structuredOutput: true,
          enforcement: "enforced_executor",
          compatibleActionClassIds: [...ACTION_CLASSES],
          disclosureClasses: ["sanitized_internal"],
        },
      ],
    }],
  };
}

function issueInput(
  overrides: Partial<IssueAutonomousActivationReceiptInput> = {},
): IssueAutonomousActivationReceiptInput {
  return {
    id: "activation-receipt-1",
    missionId: MISSION_ID,
    runId: RUN_ID,
    contractId: CONTRACT_ID,
    contractVersion: 1,
    contractHash: CONTRACT_HASH,
    generation: 1,
    runtimeGenerationHash: RUNTIME_GENERATION_HASH,
    evidencePolicyHash: autonomousActivationEvidencePolicyHash(
      EVIDENCE_REQUIREMENTS,
    ),
    brainContextPackId: CONTEXT_PACK_ID,
    planning: {
      selection: PROVIDER_PLANNING_SELECTION,
      modelAssignmentId: "assignment-vulnintel-planning",
    },
    routes: routes(),
    issuedBy: "operator",
    issuedAt: NOW,
    expiresAt: EXPIRES_AT,
    ...overrides,
  };
}

function expectIntegrityCode(
  operation: () => unknown,
  code: AutonomousActivationReceiptIntegrityError["code"],
): void {
  try {
    operation();
    throw new Error(`Expected ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(AutonomousActivationReceiptIntegrityError);
    expect((error as AutonomousActivationReceiptIntegrityError).code).toBe(code);
  }
}

describe("AutonomousActivationReceiptRepository", () => {
  test("registers migration 058 and issues one sealed immutable aggregate", () => {
    expect(listAppliedMigrations(database).find(({ version }) => version === 58))
      .toMatchObject({
        version: 58,
        name: "autonomous_activation_receipts",
      });
    const repository = new AutonomousActivationReceiptRepository(
      database,
      () => new Date(NOW),
    );
    const created = repository.issue(issueInput());

    expect(created).toMatchObject({
      id: "activation-receipt-1",
      schemaVersion: "2.4",
      missionId: MISSION_ID,
      runId: RUN_ID,
      contractId: CONTRACT_ID,
      generation: 1,
      contractHash: CONTRACT_HASH,
      runtimeGenerationHash: RUNTIME_GENERATION_HASH,
      selectedActionClassCount: 2,
      activatedActionClassCount: 2,
    });
    expect(created.planning).toMatchObject({
      route: "provider_advisory",
      plannerId: "VulnIntel",
      modelAssignmentId: "assignment-vulnintel-planning",
      primaryConfigurationId: "configuration-vulnintel-planning",
    });
    expect(
      created.items.every(({ agentId }) => agentId !== created.planning.plannerId),
    ).toBe(true);
    expect(created.selectedActionClassIds).toEqual([...ACTION_CLASSES]);
    expect(created.items.map((entry) => entry.actionClassId)).toEqual([
      "active_host_discovery",
      "port_service_enumeration",
    ]);
    expect(created.bindings).toHaveLength(1);
    expect(created.bindings[0]).toMatchObject({
      sequence: 1,
      bindingType: "launch",
      subjectId: RUN_ID,
      subjectDigest: created.receiptHash,
      contextPackId: CONTEXT_PACK_ID,
      previousBindingHash: null,
    });

    const verified = new AutonomousActivationReceiptVerifier(
      database,
      () => new Date("2026-07-28T13:00:00.000Z"),
    ).verify(created.id, {
      missionId: MISSION_ID,
      runId: RUN_ID,
      contractId: CONTRACT_ID,
      contractVersion: 1,
      contractHash: CONTRACT_HASH,
      runtimeGenerationHash: RUNTIME_GENERATION_HASH,
      evidencePolicyHash: created.evidencePolicyHash,
      brainContextPackId: CONTEXT_PACK_ID,
      selectedActionClassIds: ACTION_CLASSES,
      receiptHash: created.receiptHash,
    });
    expect(verified.valid).toBe(true);
    expect(verified.receipt.receiptHash).toBe(created.receiptHash);

    expect(() => database.prepare(`
      UPDATE autonomous_activation_receipts
      SET runtime_generation_hash = ?
      WHERE id = ?
    `).run(hash("9"), created.id)).toThrow("Autonomous activation receipts are immutable");
    expect(() => database.prepare(`
      DELETE FROM autonomous_activation_receipt_items
      WHERE receipt_id = ? AND action_class_id = ?
    `).run(created.id, ACTION_CLASSES[0])).toThrow(
      "Autonomous activation route items are immutable",
    );
  });

  test("binds local deterministic planning without a provider assignment", () => {
    setContractPlanningSelection(
      database,
      LOCAL_PLANNING_SELECTION,
    );
    const created = new AutonomousActivationReceiptRepository(database)
      .issue(issueInput({
        planning: { selection: LOCAL_PLANNING_SELECTION },
      }));

    expect(created.planning).toEqual({
      route: "local_deterministic",
      selection: LOCAL_PLANNING_SELECTION,
      selectionHash: created.planning.selectionHash,
      plannerId: "ti-scale.local-autonomous-contract-planner.v1",
      modelAssignmentId: null,
      primaryConfigurationId: null,
      fallbackConfigurationId: null,
      primaryConfigurationHash: null,
      fallbackConfigurationHash: null,
    });
    expect(
      new AutonomousActivationReceiptVerifier(
        database,
        () => new Date("2026-07-28T13:00:00.000Z"),
      ).verify(created.id, {
        planningSelectionHash: created.planning.selectionHash,
      }).valid,
    ).toBe(true);
  });

  test("issues from real catalog materialization and purpose-aware pinning", () => {
    database.prepare(`DELETE FROM agent_model_assignments`).run();
    const modelService = new ModelConfigurationService(
      new ModelConfigurationRepository(database, () => new Date(NOW)),
      {
        readRuntimeManifests: productionConfigurationManifests,
        clock: () => new Date(NOW),
      },
    );
    const catalog = modelService.catalog().items;
    const advisor = catalog.find(({ modelId, reasoningEffort }) =>
      modelId === "advisor" && reasoningEffort === null)!;
    const executor = catalog.find(({ modelId, reasoningEffort }) =>
      modelId === "executor" && reasoningEffort === null)!;
    const selection = {
      route: "provider_advisory",
      agentId: "VulnIntel",
      primaryConfigurationId: advisor.configurationId,
      fallbackConfigurationId: null,
      enforcementMode: "advisor_only",
      disclosureClass: "sanitized_internal",
      executionAuthority: "none",
    } as const satisfies AutonomousPlanningSelection;
    const planningPin = modelService.pinExactAutonomousPlanningSelection({
      selection,
      missionId: MISSION_ID,
      runId: RUN_ID,
    })!;
    const executionPins = modelService.pinExactAutonomousAssignments({
      assignments: (["ReconScout"] as const).map((agentId) => ({
        agentId,
        primaryConfigurationId: executor.configurationId,
        fallbackConfigurationId: null,
      })),
      specialistAgentIds: ["ReconScout"],
      requiredActionClassIds: ACTION_CLASSES,
      missionId: MISSION_ID,
      runId: RUN_ID,
    });
    const executionByAgent = new Map(
      executionPins.map((assignment) => [assignment.agentId, assignment.id]),
    );
    setContractPlanningSelection(database, selection);

    const created = new AutonomousActivationReceiptRepository(database)
      .issue(issueInput({
        planning: {
          selection,
          modelAssignmentId: planningPin.id,
        },
        routes: routes().map((route) => ({
          ...route,
          agentId: "ReconScout",
          executionModelAssignmentId: executionByAgent.get("ReconScout")!,
        })),
      }));

    expect(created.planning).toMatchObject({
      route: "provider_advisory",
      plannerId: "VulnIntel",
      modelAssignmentId: planningPin.id,
      primaryConfigurationId: advisor.configurationId,
    });
    expect(
      new AutonomousActivationReceiptVerifier(
        database,
        () => new Date("2026-07-28T13:00:00.000Z"),
      ).verify(created.id).valid,
    ).toBe(true);
    expect(database.prepare(`
      SELECT enforcement_mode, auth_state, health_state
      FROM model_configurations
      WHERE id = ?
    `).get(executor.configurationId)).toEqual({
      enforcement_mode: "enforced",
      auth_state: "healthy",
      health_state: "healthy",
    });
  });

  test("rejects missing, duplicate, and extra action-class routes atomically", () => {
    const repository = new AutonomousActivationReceiptRepository(database);
    expectIntegrityCode(
      () => repository.issue(issueInput({ routes: routes().slice(0, 1) })),
      "activation_receipt_class_coverage_mismatch",
    );
    expectIntegrityCode(
      () => repository.issue(issueInput({
        routes: [routes()[0]!, routes()[0]!],
      })),
      "activation_receipt_class_coverage_mismatch",
    );
    expectIntegrityCode(
      () => repository.issue(issueInput({
        routes: [
          ...routes(),
          {
            ...routes()[0]!,
            actionClassId: "out_of_contract_action",
          },
        ],
      })),
      "activation_receipt_class_coverage_mismatch",
    );
    expect(
      (database.prepare(`
        SELECT count(*) AS count FROM autonomous_activation_receipts
      `).get() as { count: number }).count,
    ).toBe(0);
    expect(
      (database.prepare(`
        SELECT count(*) AS count FROM autonomous_activation_receipt_items
      `).get() as { count: number }).count,
    ).toBe(0);
  });

  test("rejects contract mismatch and detects assignment or Context Pack drift", () => {
    const repository = new AutonomousActivationReceiptRepository(database);
    expectIntegrityCode(
      () => repository.issue(issueInput({ contractHash: hash("7") })),
      "activation_receipt_contract_mismatch",
    );
    expectIntegrityCode(
      () => repository.issue(issueInput({
        planning: { selection: LOCAL_PLANNING_SELECTION },
      })),
      "activation_receipt_contract_mismatch",
    );
    const created = repository.issue(issueInput());
    const verifier = new AutonomousActivationReceiptVerifier(
      database,
      () => new Date("2026-07-28T13:00:00.000Z"),
    );
    expectIntegrityCode(
      () => verifier.verify(created.id, { contractHash: hash("8") }),
      "activation_receipt_contract_mismatch",
    );

    database.prepare(`
      UPDATE agent_model_assignments
      SET primary_configuration_id = 'configuration-drift'
      WHERE id = 'assignment-recon-execution'
    `).run();
    expectIntegrityCode(
      () => verifier.verify(created.id),
      "activation_receipt_model_assignment_mismatch",
    );
    database.prepare(`
      UPDATE agent_model_assignments
      SET primary_configuration_id = 'configuration-recon-execution'
      WHERE id = 'assignment-recon-execution'
    `).run();

    database.prepare(`
      UPDATE agent_model_assignments
      SET primary_configuration_id = 'configuration-drift'
      WHERE id = 'assignment-vulnintel-planning'
    `).run();
    expectIntegrityCode(
      () => verifier.verify(created.id),
      "activation_receipt_model_assignment_mismatch",
    );
    database.prepare(`
      UPDATE agent_model_assignments
      SET primary_configuration_id = 'configuration-vulnintel-planning'
      WHERE id = 'assignment-vulnintel-planning'
    `).run();

    database.prepare(`
      UPDATE memory_context_packs
      SET purpose = 'tampered-intake'
      WHERE id = ?
    `).run(CONTEXT_PACK_ID);
    expectIntegrityCode(
      () => verifier.verify(created.id),
      "activation_receipt_brain_context_mismatch",
    );
  });

  test("fails closed for expiry and runtime-generation drift", () => {
    const created = new AutonomousActivationReceiptRepository(database)
      .issue(issueInput());
    expectIntegrityCode(
      () => new AutonomousActivationReceiptVerifier(
        database,
        () => new Date("2026-07-28T13:00:00.000Z"),
      ).verify(created.id, { runtimeGenerationHash: hash("6") }),
      "activation_receipt_runtime_generation_drift",
    );
    expectIntegrityCode(
      () => new AutonomousActivationReceiptVerifier(
        database,
        () => new Date(EXPIRES_AT),
      ).verify(created.id),
      "activation_receipt_expired",
    );
    expect(
      new AutonomousActivationReceiptVerifier(
        database,
        () => new Date("2026-07-28T14:00:01.000Z"),
      ).verify(created.id, { allowExpired: true }).valid,
    ).toBe(true);
  });

  test("appends a hash-chained binding ledger and forbids mutation", () => {
    const repository = new AutonomousActivationReceiptRepository(
      database,
      () => new Date("2026-07-28T12:30:00.000Z"),
    );
    const created = repository.issue(issueInput());
    const planning = repository.appendBinding({
      id: "activation-binding-planning",
      receiptId: created.id,
      bindingType: "planning",
      subjectId: "planning-generation-1",
      subjectDigest: hash("1"),
      contextPackId: CONTEXT_PACK_ID,
      boundBy: "runtime",
      boundAt: "2026-07-28T12:20:00.000Z",
    });
    const resume = repository.appendBinding({
      id: "activation-binding-resume",
      receiptId: created.id,
      bindingType: "resume",
      subjectId: "checkpoint-1",
      subjectDigest: hash("2"),
      boundBy: "runtime",
      boundAt: "2026-07-28T12:30:00.000Z",
    });
    expect(planning).toMatchObject({
      sequence: 2,
      previousBindingHash: created.bindings[0]!.bindingHash,
    });
    expect(resume).toMatchObject({
      sequence: 3,
      previousBindingHash: planning.bindingHash,
    });
    expect(
      new AutonomousActivationReceiptVerifier(
        database,
        () => new Date("2026-07-28T13:00:00.000Z"),
      ).verify(created.id).receipt.bindings.map((entry) => entry.bindingType),
    ).toEqual(["launch", "planning", "resume"]);
    expect(() => database.prepare(`
      UPDATE autonomous_activation_bindings
      SET subject_id = 'changed'
      WHERE id = ?
    `).run(planning.id)).toThrow(
      "Autonomous activation bindings are append-only",
    );
    expect(() => database.prepare(`
      DELETE FROM autonomous_activation_bindings WHERE id = ?
    `).run(resume.id)).toThrow(
      "Autonomous activation bindings are append-only",
    );
  });

  test("reopens a file database and verifies the same receipt without boot-local state", () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-activation-"));
    const filename = join(directory, "activation.sqlite");
    let first: SqliteDatabase | undefined;
    let reopened: SqliteDatabase | undefined;
    try {
      first = createDatabaseConnection({ filename });
      migrateDatabase(first);
      seedActivationBoundary(first);
      const created = new AutonomousActivationReceiptRepository(first)
        .issue(issueInput());
      const expectedReceiptHash = created.receiptHash;
      const expectedLaunchHash = created.bindings[0]!.bindingHash;
      first.close();
      first = undefined;

      reopened = createDatabaseConnection({ filename });
      expect(migrateDatabase(reopened).applied).toEqual([]);
      const read = new AutonomousActivationReceiptRepository(reopened)
        .findCurrentForRun(RUN_ID);
      expect(read?.receiptHash).toBe(expectedReceiptHash);
      expect(read?.bindings[0]?.bindingHash).toBe(expectedLaunchHash);
      expect(
        new AutonomousActivationReceiptVerifier(
          reopened,
          () => new Date("2026-07-28T13:00:00.000Z"),
        ).verifyCurrentForRun(RUN_ID, {
          runtimeGenerationHash: RUNTIME_GENERATION_HASH,
        }).valid,
      ).toBe(true);
    } finally {
      first?.close();
      reopened?.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

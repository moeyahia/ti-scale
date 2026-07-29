import { createHash } from "node:crypto";
import {
  autonomousActivationEvidencePolicyHash,
  AutonomousActivationReceiptRepository,
} from "../../../server/autonomous-runtime";
import {
  createDatabaseConnection,
  inImmediateTransaction,
  type SqliteDatabase,
} from "../../../server/db";
import type { AutonomousPlanningSelection } from "../../../server/model-config";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const ACTION_CLASS_ID = "port_service_enumeration";
const EVIDENCE_REQUIREMENT_ID = "port_service_scan_result";

export interface AutonomousActivationProofFixture {
  readonly missionId: string;
  readonly runId: string;
  readonly receiptId: string | null;
  readonly planningRoute: "local_deterministic" | "provider_advisory";
  readonly expiresAt: string | null;
}

function database(): SqliteDatabase {
  if (!E2E_DATABASE_PATH) {
    throw new Error("The isolated Playwright database path was not configured");
  }
  return createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
}

function hash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function createAutonomousActivationProofFixture(
  instanceId: string,
  options: {
    readonly planningRoute?: "local_deterministic" | "provider_advisory";
    readonly receiptState?: "valid" | "expired" | "missing";
  } = {},
): AutonomousActivationProofFixture {
  const suffix = normalizeFixtureNamespace(instanceId);
  const planningRoute = options.planningRoute ?? "provider_advisory";
  const receiptState = options.receiptState ?? "valid";
  const missionId = `mission-activation-proof-${suffix}`;
  const runId = `run-activation-proof-${suffix}`;
  const contractId = `contract-activation-proof-${suffix}`;
  const contextPackId = `context-activation-proof-${suffix}`;
  const executionAgentId = `ReconScout-${suffix}`;
  const plannerAgentId = `VulnIntel-${suffix}`;
  const executionConfigurationId = `configuration-execution-${suffix}`;
  const planningConfigurationId = `configuration-planning-${suffix}`;
  const executionAssignmentId = `assignment-execution-${suffix}`;
  const planningAssignmentId = `assignment-planning-${suffix}`;
  const receiptId = receiptState === "missing"
    ? null
    : `activation-receipt-${suffix}`;
  const issuedAt = receiptState === "expired"
    ? "2026-07-20T12:00:00.000Z"
    : "2026-07-28T12:00:00.000Z";
  const expiresAt = receiptState === "expired"
    ? "2026-07-20T14:00:00.000Z"
    : "2099-07-28T14:00:00.000Z";
  const routeExpiresAt = receiptState === "expired"
    ? "2026-07-20T15:00:00.000Z"
    : "2099-07-28T15:00:00.000Z";
  const contractHash = hash(`${suffix}:contract`);
  const runtimeGenerationHash = hash(`${suffix}:runtime`);
  const planningSelection: AutonomousPlanningSelection =
    planningRoute === "provider_advisory"
      ? {
          route: "provider_advisory",
          agentId: plannerAgentId,
          primaryConfigurationId: planningConfigurationId,
          fallbackConfigurationId: null,
          enforcementMode: "advisor_only",
          disclosureClass: "sanitized_internal",
          executionAuthority: "none",
        }
      : {
          route: "local_deterministic",
          plannerId: "ti-scale.local-autonomous-contract-planner.v1",
          enforcementMode: "local_policy",
          disclosureClass: "local_only",
          executionAuthority: "none",
        };
  const connection = database();
  try {
    inImmediateTransaction(connection, () => {
      connection.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          success_criteria_json, memory_policy_json, created_by, created_at,
          updated_at, control_plane
        ) VALUES (?, ?, 'Verify one exact aggregate Autonomous activation proof',
          'autonomous', 'active', 'verified', '[]', '{}',
          'e2e-local-operator', ?, ?, 'ti_scale')
      `).run(missionId, `Activation proof ${suffix}`, issuedAt, issuedAt);
      connection.prepare(`
        INSERT INTO mission_contracts (
          id, mission_id, version, state, contract_hash, authorization_json,
          action_policy_json, budgets_json, safe_stop_json, deliverables_json,
          memory_scopes_json, confirmed_by, confirmed_at, created_at
        ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{}', '{}', '[]', '[]',
          'e2e-local-operator', ?, ?)
      `).run(
        contractId,
        missionId,
        contractHash,
        JSON.stringify({
          allowedActionClasses: [ACTION_CLASS_ID],
          prohibitedActionClasses: [],
          evidenceRequirements: [EVIDENCE_REQUIREMENT_ID],
          planningSelection,
        }),
        issuedAt,
        issuedAt,
      );
      connection.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, contract_id,
          contract_version_bound, contract_hash_bound, progress, budget_json,
          budget_usage_json, created_at, updated_at, control_plane
        ) VALUES (?, ?, 'autonomous', 'planning', ?, 1, ?, 0.1, '{}', '{}',
          ?, ?, 'ti_scale')
      `).run(runId, missionId, contractId, contractHash, issuedAt, issuedAt);
      for (const [id, displayName] of [
        [executionAgentId, "Recon Scout"],
        [plannerAgentId, "Vulnerability Intelligence"],
      ] as const) {
        connection.prepare(`
          INSERT INTO agents (
            id, role, display_name, status, version, created_at, updated_at
          ) VALUES (?, 'reconnaissance', ?, 'available', 'e2e-1', ?, ?)
        `).run(id, displayName, issuedAt, issuedAt);
      }
      connection.prepare(`
        INSERT INTO model_configurations (
          id, provider_id, model_id, context_policy_json, capabilities_json,
          context_limit, cost_class, latency_class, disclosure_class,
          enforcement_mode, auth_state, health_state, catalog_source,
          catalog_retrieved_at, configuration_source, created_at, updated_at,
          version
        ) VALUES (?, 'e2e-provider', ?, '{}', '{}', 32768,
          'standard', 'standard', 'sanitized_internal', 'enforced', 'healthy',
          'healthy', 'e2e-catalog', ?, 'manual', ?, ?, 1)
      `).run(
        executionConfigurationId,
        `e2e-executor-${suffix}`,
        issuedAt,
        issuedAt,
        issuedAt,
      );
      if (planningRoute === "provider_advisory") {
        connection.prepare(`
          INSERT INTO model_configurations (
            id, provider_id, model_id, context_policy_json, capabilities_json,
            context_limit, cost_class, latency_class, disclosure_class,
            enforcement_mode, auth_state, health_state, catalog_source,
            catalog_retrieved_at, configuration_source, created_at, updated_at,
            version
          ) VALUES (?, 'e2e-provider', ?, '{}', '{}', 32768,
            'standard', 'standard', 'sanitized_internal', 'advisory_only',
            'healthy', 'healthy', 'e2e-catalog', ?, 'manual', ?, ?, 1)
        `).run(
          planningConfigurationId,
          `e2e-advisor-${suffix}`,
          issuedAt,
          issuedAt,
          issuedAt,
        );
      }
      connection.prepare(`
        INSERT INTO agent_model_assignments (
          id, agent_id, mission_id, run_id, step_id, assignment_purpose,
          primary_configuration_id, fallback_configuration_id,
          inheritance_level, pinned, resolution_reason, resolved_at, created_at
        ) VALUES (?, ?, ?, ?, NULL, 'execution', ?, NULL, 'run', 1,
          'Exact E2E activation execution pin', ?, ?)
      `).run(
        executionAssignmentId,
        executionAgentId,
        missionId,
        runId,
        executionConfigurationId,
        issuedAt,
        issuedAt,
      );
      if (planningRoute === "provider_advisory") {
        connection.prepare(`
          INSERT INTO agent_model_assignments (
            id, agent_id, mission_id, run_id, step_id, assignment_purpose,
            primary_configuration_id, fallback_configuration_id,
            inheritance_level, pinned, resolution_reason, resolved_at,
            created_at
          ) VALUES (?, ?, ?, ?, NULL, 'planning', ?, NULL, 'run', 1,
            'Exact E2E activation planning pin', ?, ?)
        `).run(
          planningAssignmentId,
          plannerAgentId,
          missionId,
          runId,
          planningConfigurationId,
          issuedAt,
          issuedAt,
        );
      }
      connection.prepare(`
        INSERT INTO memory_context_packs (
          id, mission_id, run_id, journey, purpose, query_redacted,
          scope_policy_json, context_budget, retrieval_metrics_json,
          created_by, created_at
        ) VALUES (?, ?, ?, 'autonomous', 'intake',
          'E2E aggregate activation context', '{}', 2048, '{}',
          'e2e-local-runtime', ?)
      `).run(contextPackId, missionId, runId, issuedAt);
    });
    if (receiptId) {
      new AutonomousActivationReceiptRepository(connection).issue({
        id: receiptId,
        missionId,
        runId,
        contractId,
        contractVersion: 1,
        contractHash,
        generation: 1,
        runtimeGenerationHash,
        evidencePolicyHash: autonomousActivationEvidencePolicyHash([
          EVIDENCE_REQUIREMENT_ID,
        ]),
        brainContextPackId: contextPackId,
        planning: planningRoute === "provider_advisory"
          ? {
              selection: planningSelection as Extract<
                AutonomousPlanningSelection,
                { route: "provider_advisory" }
              >,
              modelAssignmentId: planningAssignmentId,
            }
          : {
              selection: planningSelection as Extract<
                AutonomousPlanningSelection,
                { route: "local_deterministic" }
              >,
            },
        routes: [{
          actionClassId: ACTION_CLASS_ID,
          agentId: executionAgentId,
          executionModelAssignmentId: executionAssignmentId,
          toolId: "e2e-nmap-service-scan",
          toolBindingKind: "local",
          mcpServerId: null,
          toolActivationReceiptId: `tool-receipt-${suffix}`,
          toolActivationReceiptHash: hash(`${suffix}:tool-receipt`),
          toolManifestHash: hash(`${suffix}:tool-manifest`),
          evidenceTypeIds: [EVIDENCE_REQUIREMENT_ID],
          evidenceProducerIds: ["e2e-nmap-normalizer"],
          routeExpiresAt,
        }],
        issuedBy: "e2e-local-operator",
        issuedAt,
        expiresAt,
      });
    }
    return {
      missionId,
      runId,
      receiptId,
      planningRoute,
      expiresAt: receiptId ? expiresAt : null,
    };
  } finally {
    connection.close();
  }
}

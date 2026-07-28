import { createHash, randomUUID } from "node:crypto";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import { canonicalJson } from "../orchestration/serialization";
import {
  ModelConfigurationRepository,
  modelConfigurationBindingHash,
} from "../model-config";
import {
  AUTONOMOUS_ACTIVATION_RECEIPT_SCHEMA_VERSION,
  AutonomousActivationReceiptIntegrityError,
  type AppendAutonomousActivationBindingInput,
  type AutonomousActivationBinding,
  type AutonomousActivationModelAssignmentSnapshot,
  type AutonomousActivationPlanningInput,
  type AutonomousActivationPlanningSnapshot,
  type AutonomousActivationReceipt,
  type AutonomousActivationReceiptItem,
  type AutonomousActivationRouteInput,
  type IssueAutonomousActivationReceiptInput,
} from "./AutonomousActivationReceiptTypes";

const SHA256 = /^[a-f0-9]{64}$/u;

interface ReceiptRow {
  readonly id: string;
  readonly schema_version: "2.4";
  readonly mission_id: string;
  readonly run_id: string;
  readonly contract_id: string;
  readonly generation: number;
  readonly contract_version: number;
  readonly contract_hash: string;
  readonly runtime_generation_hash: string;
  readonly planning_route: "local_deterministic" | "provider_advisory";
  readonly planning_selection_json: string;
  readonly planning_selection_hash: string;
  readonly planning_planner_id: string;
  readonly planning_model_assignment_id: string | null;
  readonly planning_primary_configuration_id: string | null;
  readonly planning_fallback_configuration_id: string | null;
  readonly planning_primary_configuration_hash: string | null;
  readonly planning_fallback_configuration_hash: string | null;
  readonly model_assignment_set_hash: string;
  readonly evidence_policy_hash: string;
  readonly brain_context_pack_id: string;
  readonly brain_context_pack_hash: string;
  readonly selected_action_class_ids_json: string;
  readonly selected_action_class_count: number;
  readonly activated_action_class_count: number;
  readonly route_set_hash: string;
  readonly issued_by: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly receipt_hash: string;
}

interface ItemRow {
  readonly receipt_id: string;
  readonly action_class_id: string;
  readonly agent_id: string;
  readonly execution_model_assignment_id: string;
  readonly execution_primary_configuration_id: string;
  readonly execution_fallback_configuration_id: string | null;
  readonly tool_id: string;
  readonly tool_binding_kind: "local" | "mcp";
  readonly mcp_server_id: string | null;
  readonly tool_activation_receipt_id: string;
  readonly tool_activation_receipt_hash: string;
  readonly tool_manifest_hash: string;
  readonly evidence_type_ids_json: string;
  readonly evidence_producer_ids_json: string;
  readonly route_expires_at: string;
  readonly route_hash: string;
  readonly created_at: string;
}

interface BindingRow {
  readonly id: string;
  readonly receipt_id: string;
  readonly sequence: number;
  readonly binding_type: AutonomousActivationBinding["bindingType"];
  readonly subject_id: string;
  readonly subject_digest: string;
  readonly runtime_generation_hash: string;
  readonly plan_id: string | null;
  readonly step_id: string | null;
  readonly action_id: string | null;
  readonly context_pack_id: string | null;
  readonly provider_turn_id: string | null;
  readonly previous_binding_hash: string | null;
  readonly bound_by: string;
  readonly bound_at: string;
  readonly binding_hash: string;
}

interface ContractLineageRow {
  readonly mission_id: string;
  readonly mission_journey: string;
  readonly run_mission_id: string;
  readonly run_journey: string;
  readonly run_contract_id: string | null;
  readonly run_contract_version: number | null;
  readonly run_contract_hash: string | null;
  readonly contract_mission_id: string;
  readonly contract_version: number;
  readonly contract_state: string;
  readonly contract_hash: string;
  readonly action_policy_json: string;
}

interface AssignmentRow {
  readonly id: string;
  readonly agent_id: string;
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly assignment_purpose: "execution" | "planning";
  readonly primary_configuration_id: string;
  readonly fallback_configuration_id: string | null;
  readonly pinned: 0 | 1;
}

interface ConfigurationRow {
  readonly id: string;
  readonly provider_id: string;
  readonly model_id: string;
  readonly returned_model_id: string | null;
  readonly reasoning_effort: string | null;
  readonly context_policy_json: string;
  readonly capabilities_json: string;
  readonly context_limit: number | null;
  readonly cost_class: string;
  readonly latency_class: string;
  readonly disclosure_class: string;
  readonly enforcement_mode: string;
  readonly auth_state: string;
  readonly health_state: string;
  readonly catalog_source: string;
  readonly catalog_retrieved_at: string;
  readonly configuration_source: string;
  readonly prompt_template_hash: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly version: number;
}

interface ContextPackRow {
  readonly id: string;
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly action_id: string | null;
  readonly message_id: string | null;
  readonly journey: string;
  readonly purpose: string;
  readonly query_redacted: string | null;
  readonly scope_policy_json: string;
  readonly context_budget: number;
  readonly retrieval_metrics_json: string;
  readonly created_by: string;
  readonly created_at: string;
}

interface ContextItemRow {
  readonly node_id: string;
  readonly rank: number;
  readonly retrieval_score: number;
  readonly relevance_reason: string;
}

export interface AutonomousActivationRecomputedIntegrity {
  readonly selectedActionClassIds: readonly string[];
  readonly evidencePolicyHash: string;
  readonly brainContextPackHash: string;
  readonly modelAssignmentSetHash: string;
  readonly routeSetHash: string;
  readonly receiptHash: string;
  readonly routeHashes: Readonly<Record<string, string>>;
  readonly bindingHashes: readonly string[];
}

function fail(
  code: ConstructorParameters<typeof AutonomousActivationReceiptIntegrityError>[0],
  message: string,
): never {
  throw new AutonomousActivationReceiptIntegrityError(code, message);
}

export function activationSha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function activationHashCanonical(value: unknown): string {
  return activationSha256(canonicalJson(value));
}

function requireHash(value: string, label: string): string {
  const normalized = value.trim().toLowerCase();
  if (!SHA256.test(normalized)) {
    fail("activation_receipt_invalid_input", `${label} must be a lowercase SHA-256 digest`);
  }
  return normalized;
}

function requireText(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) {
    fail("activation_receipt_invalid_input", `${label} must not be empty`);
  }
  return normalized;
}

function isoTimestamp(value: string, label: string): string {
  const timestamp = new Date(value);
  if (!Number.isFinite(timestamp.getTime())) {
    fail("activation_receipt_invalid_input", `${label} must be a valid timestamp`);
  }
  return timestamp.toISOString();
}

function stringList(value: string, label: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    return fail("activation_receipt_tampered", `${label} is not valid JSON`);
  }
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
    return fail("activation_receipt_tampered", `${label} is not a string array`);
  }
  return parsed;
}

function objectJson(value: string, label: string): Readonly<Record<string, unknown>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    return fail("activation_receipt_tampered", `${label} is not valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return fail("activation_receipt_tampered", `${label} is not a JSON object`);
  }
  return parsed as Readonly<Record<string, unknown>>;
}

type ActivationPlanningSelection = AutonomousActivationPlanningInput["selection"];

function planningSelection(
  value: unknown,
  label: string,
  code: ConstructorParameters<typeof AutonomousActivationReceiptIntegrityError>[0],
): ActivationPlanningSelection {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return fail(code, `${label} must be a planning-selection object`);
  }
  const candidate = value as Readonly<Record<string, unknown>>;
  if (candidate.route === "local_deterministic") {
    const expectedKeys = [
      "disclosureClass",
      "enforcementMode",
      "executionAuthority",
      "plannerId",
      "route",
    ];
    if (
      canonicalJson(Object.keys(candidate).sort()) !== canonicalJson(expectedKeys) ||
      candidate.plannerId !== "ti-scale.local-autonomous-contract-planner.v1" ||
      candidate.enforcementMode !== "local_policy" ||
      candidate.disclosureClass !== "local_only" ||
      candidate.executionAuthority !== "none"
    ) {
      return fail(code, `${label} is not the exact local deterministic selection`);
    }
    return {
      route: "local_deterministic",
      plannerId: "ti-scale.local-autonomous-contract-planner.v1",
      enforcementMode: "local_policy",
      disclosureClass: "local_only",
      executionAuthority: "none",
    };
  }
  if (candidate.route === "provider_advisory") {
    const expectedKeys = [
      "agentId",
      "disclosureClass",
      "enforcementMode",
      "executionAuthority",
      "fallbackConfigurationId",
      "primaryConfigurationId",
      "route",
    ];
    if (
      canonicalJson(Object.keys(candidate).sort()) !== canonicalJson(expectedKeys) ||
      typeof candidate.agentId !== "string" ||
      candidate.agentId.trim().length === 0 ||
      typeof candidate.primaryConfigurationId !== "string" ||
      candidate.primaryConfigurationId.trim().length === 0 ||
      !(
        candidate.fallbackConfigurationId === null ||
        (
          typeof candidate.fallbackConfigurationId === "string" &&
          candidate.fallbackConfigurationId.trim().length > 0
        )
      ) ||
      candidate.enforcementMode !== "advisor_only" ||
      !(
        candidate.disclosureClass === "public_only" ||
        candidate.disclosureClass === "sanitized_internal"
      ) ||
      candidate.executionAuthority !== "none"
    ) {
      return fail(code, `${label} is not an exact provider advisory selection`);
    }
    if (candidate.fallbackConfigurationId === candidate.primaryConfigurationId) {
      return fail(code, `${label} fallback must differ from its primary configuration`);
    }
    return {
      route: "provider_advisory",
      agentId: candidate.agentId.trim(),
      primaryConfigurationId: candidate.primaryConfigurationId.trim(),
      fallbackConfigurationId:
        typeof candidate.fallbackConfigurationId === "string"
          ? candidate.fallbackConfigurationId.trim()
          : null,
      enforcementMode: "advisor_only",
      disclosureClass: candidate.disclosureClass,
      executionAuthority: "none",
    };
  }
  return fail(code, `${label} has an unsupported planning route`);
}

function normalizedUniqueIds(
  values: readonly string[],
  label: string,
  code: ConstructorParameters<typeof AutonomousActivationReceiptIntegrityError>[0] =
    "activation_receipt_invalid_input",
): string[] {
  const normalized = values.map((value) => value.trim());
  if (normalized.length === 0 || normalized.some((value) => value.length === 0)) {
    fail(code, `${label} must contain non-empty IDs`);
  }
  if (new Set(normalized).size !== normalized.length) {
    fail(code, `${label} must not contain duplicate IDs`);
  }
  return normalized.sort((left, right) => left.localeCompare(right, "en-US"));
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function autonomousActivationEvidencePolicyHash(
  evidenceRequirementIds: readonly string[],
): string {
  return activationHashCanonical({
    evidenceRequirementIds: normalizedUniqueIds(
      evidenceRequirementIds,
      "Evidence requirement IDs",
    ),
  });
}

function planningSnapshot(row: ReceiptRow): AutonomousActivationPlanningSnapshot {
  const selection = planningSelection(
    JSON.parse(row.planning_selection_json) as unknown,
    "Persisted activation planning selection",
    "activation_receipt_tampered",
  );
  if (
    row.planning_route === "local_deterministic" &&
    selection.route === "local_deterministic" &&
    row.planning_planner_id === selection.plannerId &&
    row.planning_model_assignment_id === null &&
    row.planning_primary_configuration_id === null &&
    row.planning_fallback_configuration_id === null &&
    row.planning_primary_configuration_hash === null &&
    row.planning_fallback_configuration_hash === null
  ) {
    return {
      route: "local_deterministic",
      selection,
      selectionHash: row.planning_selection_hash,
      plannerId: selection.plannerId,
      modelAssignmentId: null,
      primaryConfigurationId: null,
      fallbackConfigurationId: null,
      primaryConfigurationHash: null,
      fallbackConfigurationHash: null,
    };
  }
  if (
    row.planning_route === "provider_advisory" &&
    selection.route === "provider_advisory" &&
    row.planning_planner_id === selection.agentId &&
    row.planning_model_assignment_id !== null &&
    row.planning_primary_configuration_id !== null &&
    row.planning_primary_configuration_hash !== null
  ) {
    return {
      route: "provider_advisory",
      selection,
      selectionHash: row.planning_selection_hash,
      plannerId: selection.agentId,
      modelAssignmentId: row.planning_model_assignment_id,
      primaryConfigurationId: row.planning_primary_configuration_id,
      fallbackConfigurationId: row.planning_fallback_configuration_id,
      primaryConfigurationHash: row.planning_primary_configuration_hash,
      fallbackConfigurationHash: row.planning_fallback_configuration_hash,
    };
  }
  return fail(
    "activation_receipt_tampered",
    "Persisted activation planning fields do not form one valid run-level selection",
  );
}

function receipt(row: ReceiptRow, items: AutonomousActivationReceiptItem[], bindings: AutonomousActivationBinding[]): AutonomousActivationReceipt {
  return {
    id: row.id,
    schemaVersion: row.schema_version,
    missionId: row.mission_id,
    runId: row.run_id,
    contractId: row.contract_id,
    generation: row.generation,
    contractVersion: row.contract_version,
    contractHash: row.contract_hash,
    runtimeGenerationHash: row.runtime_generation_hash,
    modelAssignmentSetHash: row.model_assignment_set_hash,
    evidencePolicyHash: row.evidence_policy_hash,
    brainContextPackId: row.brain_context_pack_id,
    brainContextPackHash: row.brain_context_pack_hash,
    planning: planningSnapshot(row),
    selectedActionClassIds: stringList(
      row.selected_action_class_ids_json,
      "Activation receipt selected action classes",
    ),
    selectedActionClassCount: row.selected_action_class_count,
    activatedActionClassCount: row.activated_action_class_count,
    routeSetHash: row.route_set_hash,
    issuedBy: row.issued_by,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    receiptHash: row.receipt_hash,
    items,
    bindings,
  };
}

function item(row: ItemRow): AutonomousActivationReceiptItem {
  return {
    actionClassId: row.action_class_id,
    agentId: row.agent_id,
    executionModelAssignmentId: row.execution_model_assignment_id,
    executionPrimaryConfigurationId: row.execution_primary_configuration_id,
    executionFallbackConfigurationId: row.execution_fallback_configuration_id,
    toolId: row.tool_id,
    toolBindingKind: row.tool_binding_kind,
    mcpServerId: row.mcp_server_id,
    toolActivationReceiptId: row.tool_activation_receipt_id,
    toolActivationReceiptHash: row.tool_activation_receipt_hash,
    toolManifestHash: row.tool_manifest_hash,
    evidenceTypeIds: stringList(
      row.evidence_type_ids_json,
      `Evidence types for ${row.action_class_id}`,
    ),
    evidenceProducerIds: stringList(
      row.evidence_producer_ids_json,
      `Evidence producers for ${row.action_class_id}`,
    ),
    routeExpiresAt: row.route_expires_at,
    routeHash: row.route_hash,
    createdAt: row.created_at,
  };
}

function binding(row: BindingRow): AutonomousActivationBinding {
  return {
    id: row.id,
    receiptId: row.receipt_id,
    sequence: row.sequence,
    bindingType: row.binding_type,
    subjectId: row.subject_id,
    subjectDigest: row.subject_digest,
    runtimeGenerationHash: row.runtime_generation_hash,
    planId: row.plan_id,
    stepId: row.step_id,
    actionId: row.action_id,
    contextPackId: row.context_pack_id,
    providerTurnId: row.provider_turn_id,
    previousBindingHash: row.previous_binding_hash,
    boundBy: row.bound_by,
    boundAt: row.bound_at,
    bindingHash: row.binding_hash,
  };
}

const RECEIPT_SELECT = `
  SELECT id, schema_version, mission_id, run_id, contract_id, generation,
    contract_version, contract_hash, runtime_generation_hash,
    planning_route, planning_selection_json, planning_selection_hash,
    planning_planner_id, planning_model_assignment_id,
    planning_primary_configuration_id, planning_fallback_configuration_id,
    planning_primary_configuration_hash, planning_fallback_configuration_hash,
    model_assignment_set_hash, evidence_policy_hash, brain_context_pack_id,
    brain_context_pack_hash, selected_action_class_ids_json,
    selected_action_class_count, activated_action_class_count, route_set_hash,
    issued_by, issued_at, expires_at, receipt_hash
  FROM autonomous_activation_receipts
`;

const ITEM_SELECT = `
  SELECT receipt_id, action_class_id, agent_id,
    execution_model_assignment_id, execution_primary_configuration_id,
    execution_fallback_configuration_id, tool_id, tool_binding_kind,
    mcp_server_id, tool_activation_receipt_id,
    tool_activation_receipt_hash, tool_manifest_hash,
    evidence_type_ids_json, evidence_producer_ids_json, route_expires_at,
    route_hash, created_at
  FROM autonomous_activation_receipt_items
`;

const BINDING_SELECT = `
  SELECT id, receipt_id, sequence, binding_type, subject_id, subject_digest,
    runtime_generation_hash, plan_id, step_id, action_id, context_pack_id,
    provider_turn_id, previous_binding_hash, bound_by, bound_at, binding_hash
  FROM autonomous_activation_bindings
`;

function loadLineage(
  database: SqliteDatabase,
  missionId: string,
  runId: string,
  contractId: string,
): ContractLineageRow {
  const row = database.prepare(`
    SELECT mission.id AS mission_id, mission.journey AS mission_journey,
      run.mission_id AS run_mission_id, run.journey AS run_journey,
      run.contract_id AS run_contract_id,
      run.contract_version_bound AS run_contract_version,
      run.contract_hash_bound AS run_contract_hash,
      contract.mission_id AS contract_mission_id,
      contract.version AS contract_version, contract.state AS contract_state,
      contract.contract_hash, contract.action_policy_json
    FROM missions AS mission
    JOIN runs AS run ON run.id = ?
    JOIN mission_contracts AS contract ON contract.id = ?
    WHERE mission.id = ?
  `).get(runId, contractId, missionId) as ContractLineageRow | undefined;
  if (!row) {
    return fail(
      "activation_receipt_lineage_mismatch",
      "Autonomous activation mission, run, or contract was not found",
    );
  }
  if (
    row.mission_journey !== "autonomous" ||
    row.run_journey !== "autonomous" ||
    row.run_mission_id !== missionId ||
    row.run_contract_id !== contractId ||
    row.contract_mission_id !== missionId
  ) {
    fail(
      "activation_receipt_lineage_mismatch",
      "Autonomous activation mission, run, and contract lineage does not match",
    );
  }
  return row;
}

function contractAuthority(lineage: ContractLineageRow): {
  readonly selectedActionClassIds: string[];
  readonly evidencePolicyHash: string;
  readonly planningSelection: ActivationPlanningSelection;
  readonly planningSelectionHash: string;
} {
  const policy = objectJson(lineage.action_policy_json, "Mission contract action policy");
  const selectedRaw = policy.allowedActionClasses;
  const evidenceRaw = policy.evidenceRequirements;
  if (!Array.isArray(selectedRaw) || selectedRaw.some((item) => typeof item !== "string")) {
    fail(
      "activation_receipt_contract_mismatch",
      "Mission contract allowed action classes are malformed",
    );
  }
  if (!Array.isArray(evidenceRaw) || evidenceRaw.some((item) => typeof item !== "string")) {
    fail(
      "activation_receipt_contract_mismatch",
      "Mission contract evidence requirements are malformed",
    );
  }
  const contractPlanningSelection = planningSelection(
    policy.planningSelection,
    "Mission contract planning selection",
    "activation_receipt_contract_mismatch",
  );
  return {
    selectedActionClassIds: normalizedUniqueIds(
      selectedRaw,
      "Mission contract allowed action classes",
      "activation_receipt_contract_mismatch",
    ),
    evidencePolicyHash: autonomousActivationEvidencePolicyHash(evidenceRaw),
    planningSelection: contractPlanningSelection,
    planningSelectionHash: activationHashCanonical(contractPlanningSelection),
  };
}

function configurationSnapshot(
  database: SqliteDatabase,
  configurationId: string,
): { readonly hash: string; readonly row: ConfigurationRow } {
  const row = database.prepare(`
    SELECT id, provider_id, model_id, returned_model_id, reasoning_effort,
      context_policy_json, capabilities_json, context_limit, cost_class,
      latency_class, disclosure_class, enforcement_mode, auth_state,
      health_state, catalog_source, catalog_retrieved_at,
      configuration_source, prompt_template_hash, created_at, updated_at,
      version
    FROM model_configurations
    WHERE id = ?
  `).get(configurationId) as ConfigurationRow | undefined;
  if (!row) {
    return fail(
      "activation_receipt_model_assignment_mismatch",
      `Model configuration ${configurationId} was not found`,
    );
  }
  return {
    row,
    hash: modelConfigurationBindingHash(
      new ModelConfigurationRepository(database).getConfiguration(
        configurationId,
      ),
    ),
  };
}

function configurationEnforcementMode(
  row: ConfigurationRow,
): "enforced_executor" | "observe_only_executor" | "advisor_only" | "unavailable" {
  if (row.enforcement_mode === "enforced") return "enforced_executor";
  if (row.enforcement_mode === "observe_only") return "observe_only_executor";
  if (row.enforcement_mode === "advisory_only") return "advisor_only";
  return "unavailable";
}

function configurationAuthState(
  row: ConfigurationRow,
): "authenticated" | "unconfigured" | "invalid" | "unknown" {
  if (row.auth_state === "healthy") return "authenticated";
  if (row.auth_state === "missing") return "unconfigured";
  if (row.auth_state === "expired" || row.auth_state === "degraded") return "invalid";
  return "unknown";
}

function modelAssignmentSnapshot(
  database: SqliteDatabase,
  input: {
    readonly assignmentId: string;
    readonly expectedPurpose: "execution" | "planning";
    readonly missionId: string;
    readonly runId: string;
    readonly agentId: string;
    readonly storedPrimaryConfigurationId?: string;
    readonly storedFallbackConfigurationId?: string | null;
  },
): AutonomousActivationModelAssignmentSnapshot {
  const row = database.prepare(`
    SELECT id, agent_id, mission_id, run_id, step_id, assignment_purpose,
      primary_configuration_id, fallback_configuration_id, pinned
    FROM agent_model_assignments
    WHERE id = ?
  `).get(input.assignmentId) as AssignmentRow | undefined;
  if (
    !row ||
    row.agent_id !== input.agentId ||
    row.mission_id !== input.missionId ||
    row.run_id !== input.runId ||
    row.step_id !== null ||
    row.assignment_purpose !== input.expectedPurpose ||
    row.pinned !== 1
  ) {
    return fail(
      "activation_receipt_model_assignment_mismatch",
      `${input.expectedPurpose} model assignment ${input.assignmentId} is not the exact pinned run assignment`,
    );
  }
  if (
    input.storedPrimaryConfigurationId !== undefined &&
    row.primary_configuration_id !== input.storedPrimaryConfigurationId
  ) {
    fail(
      "activation_receipt_model_assignment_mismatch",
      `${input.expectedPurpose} model assignment ${input.assignmentId} changed its primary configuration`,
    );
  }
  if (
    input.storedFallbackConfigurationId !== undefined &&
    row.fallback_configuration_id !== input.storedFallbackConfigurationId
  ) {
    fail(
      "activation_receipt_model_assignment_mismatch",
      `${input.expectedPurpose} model assignment ${input.assignmentId} changed its fallback configuration`,
    );
  }
  const primary = configurationSnapshot(database, row.primary_configuration_id);
  const fallback = row.fallback_configuration_id
    ? configurationSnapshot(database, row.fallback_configuration_id)
    : null;
  if (input.expectedPurpose === "execution") {
    if (
      configurationEnforcementMode(primary.row) !== "enforced_executor" ||
      configurationAuthState(primary.row) !== "authenticated" ||
      primary.row.health_state !== "healthy" ||
      (
        fallback !== null &&
        (
          configurationEnforcementMode(fallback.row) !== "enforced_executor" ||
          configurationAuthState(fallback.row) !== "authenticated" ||
          fallback.row.health_state !== "healthy"
        )
      )
    ) {
      fail(
        "activation_receipt_model_assignment_mismatch",
        `Execution model assignment ${input.assignmentId} is not fully enforced and healthy`,
      );
    }
  } else if (
    configurationEnforcementMode(primary.row) !== "advisor_only" ||
    configurationAuthState(primary.row) !== "authenticated" ||
    primary.row.health_state !== "healthy" ||
    (
      fallback !== null &&
      (
        configurationEnforcementMode(fallback.row) !== "advisor_only" ||
        configurationAuthState(fallback.row) !== "authenticated" ||
        fallback.row.health_state !== "healthy"
      )
    )
  ) {
    fail(
      "activation_receipt_model_assignment_mismatch",
      `Planning model assignment ${input.assignmentId} is not authenticated, healthy, and advisor-only`,
    );
  }
  return {
    id: row.id,
    purpose: row.assignment_purpose,
    agentId: row.agent_id,
    primaryConfigurationId: row.primary_configuration_id,
    fallbackConfigurationId: row.fallback_configuration_id,
    primaryConfigurationHash: primary.hash,
    fallbackConfigurationHash: fallback?.hash ?? null,
  };
}

function contextPackHash(
  database: SqliteDatabase,
  contextPackId: string,
  missionId: string,
  runId: string,
): string {
  const pack = database.prepare(`
    SELECT id, mission_id, run_id, step_id, action_id, message_id, journey,
      purpose, query_redacted, scope_policy_json, context_budget,
      retrieval_metrics_json, created_by, created_at
    FROM memory_context_packs
    WHERE id = ?
  `).get(contextPackId) as ContextPackRow | undefined;
  if (
    !pack ||
    pack.mission_id !== missionId ||
    pack.run_id !== runId ||
    pack.journey !== "autonomous"
  ) {
    return fail(
      "activation_receipt_brain_context_mismatch",
      "Activation Context Pack does not belong to the Autonomous run",
    );
  }
  const items = database.prepare(`
    SELECT node_id, rank, retrieval_score, relevance_reason
    FROM memory_context_items
    WHERE context_pack_id = ?
    ORDER BY rank, node_id
  `).all(contextPackId) as ContextItemRow[];
  return activationHashCanonical({
    id: pack.id,
    missionId: pack.mission_id,
    runId: pack.run_id,
    stepId: pack.step_id,
    actionId: pack.action_id,
    messageId: pack.message_id,
    journey: pack.journey,
    purpose: pack.purpose,
    queryRedacted: pack.query_redacted,
    scopePolicy: objectJson(
      pack.scope_policy_json,
      `Context Pack ${contextPackId} scope policy`,
    ),
    contextBudget: pack.context_budget,
    retrievalMetrics: objectJson(
      pack.retrieval_metrics_json,
      `Context Pack ${contextPackId} retrieval metrics`,
    ),
    createdBy: pack.created_by,
    createdAt: pack.created_at,
    items: items.map((entry) => ({
      nodeId: entry.node_id,
      rank: entry.rank,
      retrievalScore: entry.retrieval_score,
      relevanceReason: entry.relevance_reason,
    })),
  });
}

function assignmentSetHash(
  assignments: readonly AutonomousActivationModelAssignmentSnapshot[],
): string {
  const unique = new Map<string, AutonomousActivationModelAssignmentSnapshot>();
  for (const assignment of assignments) {
    const key = `${assignment.purpose}\0${assignment.id}`;
    const prior = unique.get(key);
    if (prior && canonicalJson(prior) !== canonicalJson(assignment)) {
      fail(
        "activation_receipt_model_assignment_mismatch",
        `Model assignment ${assignment.id} resolved inconsistently across activation routes`,
      );
    }
    unique.set(key, assignment);
  }
  return activationHashCanonical(
    [...unique.values()].sort((left, right) =>
      `${left.purpose}:${left.id}`.localeCompare(
        `${right.purpose}:${right.id}`,
        "en-US",
      )),
  );
}

function materializePlanning(
  database: SqliteDatabase,
  input: {
    readonly planning: AutonomousActivationPlanningInput;
    readonly missionId: string;
    readonly runId: string;
  },
): {
  readonly snapshot: AutonomousActivationPlanningSnapshot;
  readonly assignment: AutonomousActivationModelAssignmentSnapshot | null;
} {
  const selection = planningSelection(
    input.planning.selection,
    "Activation planning selection",
    "activation_receipt_invalid_input",
  );
  const selectionHash = activationHashCanonical(selection);
  if (selection.route === "local_deterministic") {
    if (
      "modelAssignmentId" in input.planning &&
      input.planning.modelAssignmentId !== undefined
    ) {
      fail(
        "activation_receipt_invalid_input",
        "Local deterministic planning cannot bind a provider model assignment",
      );
    }
    return {
      assignment: null,
      snapshot: {
        route: "local_deterministic",
        selection,
        selectionHash,
        plannerId: selection.plannerId,
        modelAssignmentId: null,
        primaryConfigurationId: null,
        fallbackConfigurationId: null,
        primaryConfigurationHash: null,
        fallbackConfigurationHash: null,
      },
    };
  }
  if (
    input.planning.selection.route !== "provider_advisory" ||
    !("modelAssignmentId" in input.planning) ||
    typeof input.planning.modelAssignmentId !== "string"
  ) {
    return fail(
      "activation_receipt_invalid_input",
      "Provider advisory planning requires one exact planning model assignment",
    );
  }
  const assignment = modelAssignmentSnapshot(database, {
    assignmentId: requireText(
      input.planning.modelAssignmentId,
      "Planning model assignment ID",
    ),
    expectedPurpose: "planning",
    missionId: input.missionId,
    runId: input.runId,
    agentId: selection.agentId,
    storedPrimaryConfigurationId: selection.primaryConfigurationId,
    storedFallbackConfigurationId: selection.fallbackConfigurationId,
  });
  const primary = configurationSnapshot(
    database,
    assignment.primaryConfigurationId,
  );
  const fallback = assignment.fallbackConfigurationId
    ? configurationSnapshot(database, assignment.fallbackConfigurationId)
    : null;
  if (
    primary.row.disclosure_class !== selection.disclosureClass ||
    (
      fallback !== null &&
      fallback.row.disclosure_class !== selection.disclosureClass
    )
  ) {
    fail(
      "activation_receipt_model_assignment_mismatch",
      "Provider planning configuration does not match the signed disclosure class",
    );
  }
  return {
    assignment,
    snapshot: {
      route: "provider_advisory",
      selection,
      selectionHash,
      plannerId: selection.agentId,
      modelAssignmentId: assignment.id,
      primaryConfigurationId: assignment.primaryConfigurationId,
      fallbackConfigurationId: assignment.fallbackConfigurationId,
      primaryConfigurationHash: primary.hash,
      fallbackConfigurationHash: fallback?.hash ?? null,
    },
  };
}

function routeHash(
  receiptId: string,
  runtimeGenerationHash: string,
  route: Omit<AutonomousActivationReceiptItem, "routeHash" | "createdAt">,
  execution: AutonomousActivationModelAssignmentSnapshot,
): string {
  return activationHashCanonical({
    receiptId,
    runtimeGenerationHash,
    actionClassId: route.actionClassId,
    agentId: route.agentId,
    executionModelAssignment: execution,
    tool: {
      id: route.toolId,
      bindingKind: route.toolBindingKind,
      mcpServerId: route.mcpServerId,
      activationReceiptId: route.toolActivationReceiptId,
      activationReceiptHash: route.toolActivationReceiptHash,
      manifestHash: route.toolManifestHash,
    },
    evidenceTypeIds: route.evidenceTypeIds,
    evidenceProducerIds: route.evidenceProducerIds,
    routeExpiresAt: route.routeExpiresAt,
  });
}

function receiptHash(input: Omit<AutonomousActivationReceipt, "items" | "bindings" | "receiptHash">): string {
  return activationHashCanonical(input);
}

function bindingHash(
  receiptHashValue: string,
  input: Omit<AutonomousActivationBinding, "bindingHash">,
): string {
  return activationHashCanonical({
    receiptHash: receiptHashValue,
    ...input,
  });
}

function materializeRoute(
  database: SqliteDatabase,
  input: {
    readonly receiptId: string;
    readonly missionId: string;
    readonly runId: string;
    readonly runtimeGenerationHash: string;
    readonly route: AutonomousActivationRouteInput;
    readonly receiptExpiresAt: string;
    readonly createdAt: string;
  },
): {
  readonly item: AutonomousActivationReceiptItem;
  readonly execution: AutonomousActivationModelAssignmentSnapshot;
} {
  const actionClassId = requireText(input.route.actionClassId, "Action class ID");
  const agentId = requireText(input.route.agentId, "Agent ID");
  const execution = modelAssignmentSnapshot(database, {
    assignmentId: requireText(
      input.route.executionModelAssignmentId,
      "Execution model assignment ID",
    ),
    expectedPurpose: "execution",
    missionId: input.missionId,
    runId: input.runId,
    agentId,
  });
  const toolBindingKind = input.route.toolBindingKind;
  const mcpServerId = input.route.mcpServerId
    ? requireText(input.route.mcpServerId, "MCP server ID")
    : null;
  if (
    (toolBindingKind === "local" && mcpServerId !== null) ||
    (toolBindingKind === "mcp" && mcpServerId === null)
  ) {
    fail(
      "activation_receipt_invalid_input",
      "Local tool routes cannot name an MCP server and MCP routes must name one",
    );
  }
  if (
    mcpServerId &&
    !database.prepare(`SELECT 1 FROM mcp_servers WHERE id = ?`).get(mcpServerId)
  ) {
    fail(
      "activation_receipt_invalid_input",
      `MCP server ${mcpServerId} was not found`,
    );
  }
  const evidenceTypeIds = normalizedUniqueIds(
    input.route.evidenceTypeIds,
    `Evidence types for ${actionClassId}`,
  );
  const evidenceProducerIds = normalizedUniqueIds(
    input.route.evidenceProducerIds,
    `Evidence producers for ${actionClassId}`,
  );
  const routeExpiresAt = isoTimestamp(
    input.route.routeExpiresAt,
    `Route expiry for ${actionClassId}`,
  );
  if (routeExpiresAt < input.receiptExpiresAt) {
    fail(
      "activation_receipt_invalid_input",
      `Route ${actionClassId} expires before the aggregate receipt`,
    );
  }
  const withoutHash: Omit<AutonomousActivationReceiptItem, "routeHash" | "createdAt"> = {
    actionClassId,
    agentId,
    executionModelAssignmentId: execution.id,
    executionPrimaryConfigurationId: execution.primaryConfigurationId,
    executionFallbackConfigurationId: execution.fallbackConfigurationId,
    toolId: requireText(input.route.toolId, `Tool ID for ${actionClassId}`),
    toolBindingKind,
    mcpServerId,
    toolActivationReceiptId: requireText(
      input.route.toolActivationReceiptId,
      `Tool activation receipt ID for ${actionClassId}`,
    ),
    toolActivationReceiptHash: requireHash(
      input.route.toolActivationReceiptHash,
      `Tool activation receipt hash for ${actionClassId}`,
    ),
    toolManifestHash: requireHash(
      input.route.toolManifestHash,
      `Tool manifest hash for ${actionClassId}`,
    ),
    evidenceTypeIds,
    evidenceProducerIds,
    routeExpiresAt,
  };
  return {
    execution,
    item: {
      ...withoutHash,
      routeHash: routeHash(
        input.receiptId,
        input.runtimeGenerationHash,
        withoutHash,
        execution,
      ),
      createdAt: input.createdAt,
    },
  };
}

function insertBinding(
  database: SqliteDatabase,
  receiptRecord: AutonomousActivationReceipt,
  input: {
    readonly id: string;
    readonly bindingType: AutonomousActivationBinding["bindingType"];
    readonly subjectId: string;
    readonly subjectDigest: string;
    readonly planId: string | null;
    readonly stepId: string | null;
    readonly actionId: string | null;
    readonly contextPackId: string | null;
    readonly providerTurnId: string | null;
    readonly boundBy: string;
    readonly boundAt: string;
  },
): AutonomousActivationBinding {
  const prior = database.prepare(`
    ${BINDING_SELECT}
    WHERE receipt_id = ?
    ORDER BY sequence DESC
    LIMIT 1
  `).get(receiptRecord.id) as BindingRow | undefined;
  const sequence = (prior?.sequence ?? 0) + 1;
  const withoutHash: Omit<AutonomousActivationBinding, "bindingHash"> = {
    id: input.id,
    receiptId: receiptRecord.id,
    sequence,
    bindingType: input.bindingType,
    subjectId: requireText(input.subjectId, "Activation binding subject ID"),
    subjectDigest: requireHash(input.subjectDigest, "Activation binding subject digest"),
    runtimeGenerationHash: receiptRecord.runtimeGenerationHash,
    planId: input.planId,
    stepId: input.stepId,
    actionId: input.actionId,
    contextPackId: input.contextPackId,
    providerTurnId: input.providerTurnId,
    previousBindingHash: prior?.binding_hash ?? null,
    boundBy: requireText(input.boundBy, "Activation binding actor"),
    boundAt: isoTimestamp(input.boundAt, "Activation binding time"),
  };
  const created: AutonomousActivationBinding = {
    ...withoutHash,
    bindingHash: bindingHash(receiptRecord.receiptHash, withoutHash),
  };
  database.prepare(`
    INSERT INTO autonomous_activation_bindings (
      id, receipt_id, sequence, binding_type, subject_id, subject_digest,
      runtime_generation_hash, plan_id, step_id, action_id, context_pack_id,
      provider_turn_id, previous_binding_hash, bound_by, bound_at, binding_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    created.id,
    created.receiptId,
    created.sequence,
    created.bindingType,
    created.subjectId,
    created.subjectDigest,
    created.runtimeGenerationHash,
    created.planId,
    created.stepId,
    created.actionId,
    created.contextPackId,
    created.providerTurnId,
    created.previousBindingHash,
    created.boundBy,
    created.boundAt,
    created.bindingHash,
  );
  return created;
}

export class AutonomousActivationReceiptRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  issue(input: IssueAutonomousActivationReceiptInput): AutonomousActivationReceipt {
    return inImmediateTransaction(this.database, () => {
      const receiptId = input.id
        ? requireText(input.id, "Activation receipt ID")
        : `autonomous_activation_receipt_${randomUUID()}`;
      const issuedAt = isoTimestamp(
        input.issuedAt ?? this.clock().toISOString(),
        "Activation issue time",
      );
      const expiresAt = isoTimestamp(input.expiresAt, "Activation expiry time");
      if (expiresAt <= issuedAt) {
        fail(
          "activation_receipt_invalid_input",
          "Activation receipt expiry must be after its issue time",
        );
      }
      if (!Number.isSafeInteger(input.generation) || input.generation <= 0) {
        fail(
          "activation_receipt_invalid_input",
          "Activation receipt generation must be a positive integer",
        );
      }
      const lineage = loadLineage(
        this.database,
        input.missionId,
        input.runId,
        input.contractId,
      );
      if (
        lineage.contract_state !== "confirmed" ||
        lineage.contract_version !== input.contractVersion ||
        lineage.contract_hash !== input.contractHash ||
        lineage.run_contract_version !== input.contractVersion ||
        lineage.run_contract_hash !== input.contractHash
      ) {
        fail(
          "activation_receipt_contract_mismatch",
          "Activation input does not match the exact confirmed contract bound to the run",
        );
      }
      const contract = contractAuthority(lineage);
      const evidencePolicyHash = requireHash(
        input.evidencePolicyHash,
        "Evidence policy hash",
      );
      if (evidencePolicyHash !== contract.evidencePolicyHash) {
        fail(
          "activation_receipt_contract_mismatch",
          "Activation evidence policy hash does not match the signed contract",
        );
      }
      const runtimeGenerationHash = requireHash(
        input.runtimeGenerationHash,
        "Runtime generation hash",
      );
      const brainContextPackHash = contextPackHash(
        this.database,
        input.brainContextPackId,
        input.missionId,
        input.runId,
      );
      const planning = materializePlanning(this.database, {
        planning: input.planning,
        missionId: input.missionId,
        runId: input.runId,
      });
      if (
        canonicalJson(planning.snapshot.selection) !==
          canonicalJson(contract.planningSelection) ||
        planning.snapshot.selectionHash !== contract.planningSelectionHash
      ) {
        fail(
          "activation_receipt_contract_mismatch",
          "Activation planning selection does not match the exact run-level selection signed into the contract",
        );
      }
      const routeClassIds = normalizedUniqueIds(
        input.routes.map((route) => route.actionClassId),
        "Activation route action classes",
        "activation_receipt_class_coverage_mismatch",
      );
      if (!sameStrings(routeClassIds, contract.selectedActionClassIds)) {
        fail(
          "activation_receipt_class_coverage_mismatch",
          "Activation routes must cover every signed action class exactly once",
        );
      }
      const materials = input.routes.map((route) =>
        materializeRoute(this.database, {
          receiptId,
          missionId: input.missionId,
          runId: input.runId,
          runtimeGenerationHash,
          route,
          receiptExpiresAt: expiresAt,
          createdAt: issuedAt,
        })
      ).sort((left, right) =>
        left.item.actionClassId.localeCompare(right.item.actionClassId, "en-US")
      );
      const assignments = materials.map((material) => material.execution);
      if (planning.assignment) assignments.push(planning.assignment);
      const modelAssignmentSetHash = assignmentSetHash(assignments);
      const routeSetHash = activationHashCanonical(
        materials.map(({ item: routeItem }) => ({
          actionClassId: routeItem.actionClassId,
          routeHash: routeItem.routeHash,
        })),
      );
      const base: Omit<AutonomousActivationReceipt, "items" | "bindings" | "receiptHash"> = {
        id: receiptId,
        schemaVersion: AUTONOMOUS_ACTIVATION_RECEIPT_SCHEMA_VERSION,
        missionId: input.missionId,
        runId: input.runId,
        contractId: input.contractId,
        generation: input.generation,
        contractVersion: input.contractVersion,
        contractHash: requireHash(input.contractHash, "Contract hash"),
        runtimeGenerationHash,
        planning: planning.snapshot,
        modelAssignmentSetHash,
        evidencePolicyHash,
        brainContextPackId: input.brainContextPackId,
        brainContextPackHash,
        selectedActionClassIds: contract.selectedActionClassIds,
        selectedActionClassCount: contract.selectedActionClassIds.length,
        activatedActionClassCount: materials.length,
        routeSetHash,
        issuedBy: requireText(input.issuedBy, "Activation receipt issuer"),
        issuedAt,
        expiresAt,
      };
      const createdReceipt: AutonomousActivationReceipt = {
        ...base,
        receiptHash: receiptHash(base),
        items: materials.map((material) => material.item),
        bindings: [],
      };
      this.database.prepare(`
        INSERT INTO autonomous_activation_receipts (
          id, schema_version, mission_id, run_id, contract_id, generation,
          contract_version, contract_hash, runtime_generation_hash,
          planning_route, planning_selection_json, planning_selection_hash,
          planning_planner_id, planning_model_assignment_id,
          planning_primary_configuration_id,
          planning_fallback_configuration_id,
          planning_primary_configuration_hash,
          planning_fallback_configuration_hash, model_assignment_set_hash,
          evidence_policy_hash,
          brain_context_pack_id, brain_context_pack_hash,
          selected_action_class_ids_json, selected_action_class_count,
          activated_action_class_count, route_set_hash, issued_by, issued_at,
          expires_at, receipt_hash
        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
      `).run(
        createdReceipt.id,
        createdReceipt.schemaVersion,
        createdReceipt.missionId,
        createdReceipt.runId,
        createdReceipt.contractId,
        createdReceipt.generation,
        createdReceipt.contractVersion,
        createdReceipt.contractHash,
        createdReceipt.runtimeGenerationHash,
        createdReceipt.planning.route,
        canonicalJson(createdReceipt.planning.selection),
        createdReceipt.planning.selectionHash,
        createdReceipt.planning.plannerId,
        createdReceipt.planning.modelAssignmentId,
        createdReceipt.planning.primaryConfigurationId,
        createdReceipt.planning.fallbackConfigurationId,
        createdReceipt.planning.primaryConfigurationHash,
        createdReceipt.planning.fallbackConfigurationHash,
        createdReceipt.modelAssignmentSetHash,
        createdReceipt.evidencePolicyHash,
        createdReceipt.brainContextPackId,
        createdReceipt.brainContextPackHash,
        canonicalJson(createdReceipt.selectedActionClassIds),
        createdReceipt.selectedActionClassCount,
        createdReceipt.activatedActionClassCount,
        createdReceipt.routeSetHash,
        createdReceipt.issuedBy,
        createdReceipt.issuedAt,
        createdReceipt.expiresAt,
        createdReceipt.receiptHash,
      );
      const insertItem = this.database.prepare(`
        INSERT INTO autonomous_activation_receipt_items (
          receipt_id, action_class_id, agent_id,
          execution_model_assignment_id, execution_primary_configuration_id,
          execution_fallback_configuration_id, tool_id, tool_binding_kind,
          mcp_server_id, tool_activation_receipt_id,
          tool_activation_receipt_hash, tool_manifest_hash,
          evidence_type_ids_json, evidence_producer_ids_json,
          route_expires_at, route_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const routeItem of createdReceipt.items) {
        insertItem.run(
          createdReceipt.id,
          routeItem.actionClassId,
          routeItem.agentId,
          routeItem.executionModelAssignmentId,
          routeItem.executionPrimaryConfigurationId,
          routeItem.executionFallbackConfigurationId,
          routeItem.toolId,
          routeItem.toolBindingKind,
          routeItem.mcpServerId,
          routeItem.toolActivationReceiptId,
          routeItem.toolActivationReceiptHash,
          routeItem.toolManifestHash,
          canonicalJson(routeItem.evidenceTypeIds),
          canonicalJson(routeItem.evidenceProducerIds),
          routeItem.routeExpiresAt,
          routeItem.routeHash,
          routeItem.createdAt,
        );
      }
      const launch = insertBinding(this.database, createdReceipt, {
        id: `autonomous_activation_binding_${randomUUID()}`,
        bindingType: "launch",
        subjectId: createdReceipt.runId,
        subjectDigest: createdReceipt.receiptHash,
        planId: null,
        stepId: null,
        actionId: null,
        contextPackId: createdReceipt.brainContextPackId,
        providerTurnId: null,
        boundBy: createdReceipt.issuedBy,
        boundAt: createdReceipt.issuedAt,
      });
      return {
        ...createdReceipt,
        bindings: [launch],
      };
    });
  }

  appendBinding(input: AppendAutonomousActivationBindingInput): AutonomousActivationBinding {
    return inImmediateTransaction(this.database, () => {
      if (input.bindingType === "launch") {
        fail(
          "activation_receipt_invalid_input",
          "The launch seal is created only by receipt issuance",
        );
      }
      const receiptRecord = this.getById(input.receiptId);
      const boundAt = isoTimestamp(
        input.boundAt ?? this.clock().toISOString(),
        "Activation binding time",
      );
      if (boundAt > receiptRecord.expiresAt) {
        fail(
          "activation_receipt_expired",
          "The Autonomous activation receipt expired before this binding",
        );
      }
      return insertBinding(this.database, receiptRecord, {
        id: input.id
          ? requireText(input.id, "Activation binding ID")
          : `autonomous_activation_binding_${randomUUID()}`,
        bindingType: input.bindingType,
        subjectId: input.subjectId,
        subjectDigest: input.subjectDigest,
        planId: input.planId ?? null,
        stepId: input.stepId ?? null,
        actionId: input.actionId ?? null,
        contextPackId: input.contextPackId ?? null,
        providerTurnId: input.providerTurnId ?? null,
        boundBy: input.boundBy,
        boundAt,
      });
    });
  }

  findById(receiptId: string): AutonomousActivationReceipt | null {
    const row = this.database.prepare(`${RECEIPT_SELECT} WHERE id = ?`)
      .get(receiptId) as ReceiptRow | undefined;
    if (!row) return null;
    const items = (this.database.prepare(`
      ${ITEM_SELECT}
      WHERE receipt_id = ?
      ORDER BY action_class_id
    `).all(receiptId) as ItemRow[]).map(item);
    const bindings = (this.database.prepare(`
      ${BINDING_SELECT}
      WHERE receipt_id = ?
      ORDER BY sequence
    `).all(receiptId) as BindingRow[]).map(binding);
    return receipt(row, items, bindings);
  }

  getById(receiptId: string): AutonomousActivationReceipt {
    return this.findById(receiptId) ?? fail(
      "activation_receipt_not_found",
      `Autonomous activation receipt ${receiptId} was not found`,
    );
  }

  findCurrentForRun(runId: string): AutonomousActivationReceipt | null {
    const row = this.database.prepare(`
      ${RECEIPT_SELECT}
      WHERE run_id = ?
      ORDER BY generation DESC, issued_at DESC, id DESC
      LIMIT 1
    `).get(runId) as ReceiptRow | undefined;
    return row ? this.getById(row.id) : null;
  }

  /**
   * Bounded immutable history for one exact run. The aggregate rows remain
   * newest-first even if two generations were issued at the same timestamp.
   */
  listForRun(runId: string, limit = 100): AutonomousActivationReceipt[] {
    const normalizedRunId = requireText(runId, "Activation receipt run ID");
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      fail(
        "activation_receipt_invalid_input",
        "Activation receipt history limit must be an integer from 1 through 100",
      );
    }
    const rows = this.database.prepare(`
      ${RECEIPT_SELECT}
      WHERE run_id = ?
      ORDER BY generation DESC, issued_at DESC, id DESC
      LIMIT ?
    `).all(normalizedRunId, limit) as ReceiptRow[];
    return rows.map((row) => this.getById(row.id));
  }
}

export function recomputeAutonomousActivationReceiptIntegrity(
  database: SqliteDatabase,
  receiptRecord: AutonomousActivationReceipt,
): AutonomousActivationRecomputedIntegrity {
  const lineage = loadLineage(
    database,
    receiptRecord.missionId,
    receiptRecord.runId,
    receiptRecord.contractId,
  );
  if (
    lineage.contract_version !== receiptRecord.contractVersion ||
    lineage.contract_hash !== receiptRecord.contractHash ||
    lineage.run_contract_version !== receiptRecord.contractVersion ||
    lineage.run_contract_hash !== receiptRecord.contractHash
  ) {
    fail(
      "activation_receipt_contract_mismatch",
      "Persisted activation receipt no longer matches its run-bound contract",
    );
  }
  const contract = contractAuthority(lineage);
  const storedClasses = normalizedUniqueIds(
    receiptRecord.selectedActionClassIds,
    "Persisted activation action classes",
    "activation_receipt_class_coverage_mismatch",
  );
  const itemClasses = normalizedUniqueIds(
    receiptRecord.items.map((entry) => entry.actionClassId),
    "Persisted activation route action classes",
    "activation_receipt_class_coverage_mismatch",
  );
  if (
    !sameStrings(storedClasses, contract.selectedActionClassIds) ||
    !sameStrings(itemClasses, contract.selectedActionClassIds) ||
    receiptRecord.selectedActionClassCount !== contract.selectedActionClassIds.length ||
    receiptRecord.activatedActionClassCount !== receiptRecord.items.length
  ) {
    fail(
      "activation_receipt_class_coverage_mismatch",
      "Persisted activation receipt does not cover every signed action class exactly once",
    );
  }
  const planningInput: AutonomousActivationPlanningInput =
    receiptRecord.planning.route === "local_deterministic"
      ? { selection: receiptRecord.planning.selection }
      : {
          selection: receiptRecord.planning.selection,
          modelAssignmentId: receiptRecord.planning.modelAssignmentId,
        };
  const planning = materializePlanning(database, {
    planning: planningInput,
    missionId: receiptRecord.missionId,
    runId: receiptRecord.runId,
  });
  if (
    canonicalJson(planning.snapshot) !== canonicalJson(receiptRecord.planning) ||
    canonicalJson(planning.snapshot.selection) !==
      canonicalJson(contract.planningSelection) ||
    planning.snapshot.selectionHash !== contract.planningSelectionHash
  ) {
    fail(
      "activation_receipt_model_assignment_mismatch",
      "Persisted run-level planning selection or provider pin changed after issuance",
    );
  }
  const assignments: AutonomousActivationModelAssignmentSnapshot[] = [];
  if (planning.assignment) assignments.push(planning.assignment);
  const routeHashes: Record<string, string> = {};
  for (const entry of receiptRecord.items) {
    const execution = modelAssignmentSnapshot(database, {
      assignmentId: entry.executionModelAssignmentId,
      expectedPurpose: "execution",
      missionId: receiptRecord.missionId,
      runId: receiptRecord.runId,
      agentId: entry.agentId,
      storedPrimaryConfigurationId: entry.executionPrimaryConfigurationId,
      storedFallbackConfigurationId: entry.executionFallbackConfigurationId,
    });
    assignments.push(execution);
    const withoutHash: Omit<AutonomousActivationReceiptItem, "routeHash" | "createdAt"> = {
      actionClassId: entry.actionClassId,
      agentId: entry.agentId,
      executionModelAssignmentId: entry.executionModelAssignmentId,
      executionPrimaryConfigurationId: entry.executionPrimaryConfigurationId,
      executionFallbackConfigurationId: entry.executionFallbackConfigurationId,
      toolId: entry.toolId,
      toolBindingKind: entry.toolBindingKind,
      mcpServerId: entry.mcpServerId,
      toolActivationReceiptId: entry.toolActivationReceiptId,
      toolActivationReceiptHash: entry.toolActivationReceiptHash,
      toolManifestHash: entry.toolManifestHash,
      evidenceTypeIds: normalizedUniqueIds(
        entry.evidenceTypeIds,
        `Persisted evidence types for ${entry.actionClassId}`,
        "activation_receipt_tampered",
      ),
      evidenceProducerIds: normalizedUniqueIds(
        entry.evidenceProducerIds,
        `Persisted evidence producers for ${entry.actionClassId}`,
        "activation_receipt_tampered",
      ),
      routeExpiresAt: entry.routeExpiresAt,
    };
    const recomputed = routeHash(
      receiptRecord.id,
      receiptRecord.runtimeGenerationHash,
      withoutHash,
      execution,
    );
    if (recomputed !== entry.routeHash) {
      fail(
        "activation_receipt_tampered",
        `Activation route ${entry.actionClassId} failed its canonical hash`,
      );
    }
    routeHashes[entry.actionClassId] = recomputed;
  }
  const modelAssignmentSetHash = assignmentSetHash(assignments);
  const routeSetHash = activationHashCanonical(
    Object.entries(routeHashes)
      .sort(([left], [right]) => left.localeCompare(right, "en-US"))
      .map(([actionClassId, hash]) => ({ actionClassId, routeHash: hash })),
  );
  const brainContextPackHash = contextPackHash(
    database,
    receiptRecord.brainContextPackId,
    receiptRecord.missionId,
    receiptRecord.runId,
  );
  const evidencePolicyHash = contract.evidencePolicyHash;
  const base: Omit<AutonomousActivationReceipt, "items" | "bindings" | "receiptHash"> = {
    id: receiptRecord.id,
    schemaVersion: receiptRecord.schemaVersion,
    missionId: receiptRecord.missionId,
    runId: receiptRecord.runId,
    contractId: receiptRecord.contractId,
    generation: receiptRecord.generation,
    contractVersion: receiptRecord.contractVersion,
    contractHash: receiptRecord.contractHash,
    runtimeGenerationHash: receiptRecord.runtimeGenerationHash,
    planning: planning.snapshot,
    modelAssignmentSetHash,
    evidencePolicyHash,
    brainContextPackId: receiptRecord.brainContextPackId,
    brainContextPackHash,
    selectedActionClassIds: storedClasses,
    selectedActionClassCount: receiptRecord.selectedActionClassCount,
    activatedActionClassCount: receiptRecord.activatedActionClassCount,
    routeSetHash,
    issuedBy: receiptRecord.issuedBy,
    issuedAt: receiptRecord.issuedAt,
    expiresAt: receiptRecord.expiresAt,
  };
  const recomputedReceiptHash = receiptHash(base);
  if (modelAssignmentSetHash !== receiptRecord.modelAssignmentSetHash) {
    fail(
      "activation_receipt_model_assignment_mismatch",
      "Autonomous activation model-assignment set changed after issuance",
    );
  }
  if (brainContextPackHash !== receiptRecord.brainContextPackHash) {
    fail(
      "activation_receipt_brain_context_mismatch",
      "Autonomous activation Brain Context Pack changed after issuance",
    );
  }
  if (evidencePolicyHash !== receiptRecord.evidencePolicyHash) {
    fail(
      "activation_receipt_contract_mismatch",
      "Autonomous activation evidence policy changed after issuance",
    );
  }
  if (
    routeSetHash !== receiptRecord.routeSetHash ||
    recomputedReceiptHash !== receiptRecord.receiptHash
  ) {
    fail(
      "activation_receipt_tampered",
      "Autonomous activation receipt failed canonical integrity verification",
    );
  }
  if (
    receiptRecord.bindings.length === 0 ||
    receiptRecord.bindings[0]?.bindingType !== "launch" ||
    receiptRecord.bindings[0]?.subjectId !== receiptRecord.runId ||
    receiptRecord.bindings[0]?.subjectDigest !== receiptRecord.receiptHash ||
    receiptRecord.bindings[0]?.contextPackId !== receiptRecord.brainContextPackId
  ) {
    fail(
      "activation_binding_chain_invalid",
      "Autonomous activation receipt is missing its exact launch seal",
    );
  }
  const bindingHashes: string[] = [];
  for (const [index, entry] of receiptRecord.bindings.entries()) {
    const expectedSequence = index + 1;
    const expectedPrevious = index === 0 ? null : bindingHashes[index - 1] ?? null;
    if (
      entry.sequence !== expectedSequence ||
      entry.previousBindingHash !== expectedPrevious ||
      entry.runtimeGenerationHash !== receiptRecord.runtimeGenerationHash
    ) {
      fail(
        "activation_binding_chain_invalid",
        "Autonomous activation binding sequence or generation is invalid",
      );
    }
    const withoutHash: Omit<AutonomousActivationBinding, "bindingHash"> = {
      id: entry.id,
      receiptId: entry.receiptId,
      sequence: entry.sequence,
      bindingType: entry.bindingType,
      subjectId: entry.subjectId,
      subjectDigest: entry.subjectDigest,
      runtimeGenerationHash: entry.runtimeGenerationHash,
      planId: entry.planId,
      stepId: entry.stepId,
      actionId: entry.actionId,
      contextPackId: entry.contextPackId,
      providerTurnId: entry.providerTurnId,
      previousBindingHash: entry.previousBindingHash,
      boundBy: entry.boundBy,
      boundAt: entry.boundAt,
    };
    const recomputed = bindingHash(receiptRecord.receiptHash, withoutHash);
    if (recomputed !== entry.bindingHash) {
      fail(
        "activation_binding_chain_invalid",
        `Autonomous activation binding ${entry.id} failed its hash`,
      );
    }
    bindingHashes.push(recomputed);
  }
  return {
    selectedActionClassIds: storedClasses,
    evidencePolicyHash,
    brainContextPackHash,
    modelAssignmentSetHash,
    routeSetHash,
    receiptHash: recomputedReceiptHash,
    routeHashes,
    bindingHashes,
  };
}

import type { SqliteDatabase } from "../db";
import {
  PRODUCT_AGENT_IDS,
  PRODUCT_AGENT_REGISTRY,
  type ProductAgentId,
} from "../agents";
import {
  ModelConfigurationError,
  ModelConfigurationRepository,
  type StoredModelConfiguration,
} from "../model-config";
import {
  AGENT_RUNTIME_BINDING_SCHEMA_VERSION,
  AgentRuntimeBindingError,
  type AgentRuntimeBinding,
  type AgentRunRuntimeBinding,
  type ModelAssignmentBindingScope,
  type ProductAgentResolutionSource,
  type ResolveAgentRuntimeBindingInput,
} from "./types";

interface StepScopeRow {
  readonly step_id: string;
  readonly step_run_id: string;
  readonly assigned_agent_id: string | null;
  readonly action_class: string | null;
  readonly mission_id: string;
  readonly journey: string;
}

interface ModelAssignmentRow {
  readonly id: string;
  readonly agent_id: string;
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly primary_configuration_id: string;
  readonly fallback_configuration_id: string | null;
  readonly resolution_reason: string;
  readonly resolved_at: string;
}

interface AutonomousContractAssignmentRow {
  readonly run_mission_id: string;
  readonly contract_id: string | null;
  readonly contract_version_bound: number | null;
  readonly contract_hash_bound: string | null;
  readonly contract_mission_id: string | null;
  readonly contract_version: number | null;
  readonly contract_state: string | null;
  readonly contract_hash: string | null;
  readonly action_policy_json: string | null;
}

function fail(
  code: AgentRuntimeBindingError["code"],
  message: string,
  category: AgentRuntimeBindingError["category"],
  remediation: string,
): never {
  throw new AgentRuntimeBindingError(code, message, category, remediation);
}

function requiredId(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) {
    fail(
      "agent_runtime_binding_invalid_input",
      `${label} is required`,
      "invalid_input",
      "Supply exact canonical mission, run, and plan-step IDs.",
    );
  }
  return normalized;
}

function actionClassOwners(actionClassId: string): readonly ProductAgentId[] {
  return PRODUCT_AGENT_REGISTRY
    .filter((agent) =>
      agent.capabilities.some((capability) =>
        capability.actionClassIds.includes(
          actionClassId as (typeof capability.actionClassIds)[number],
        )))
    .map(({ id }) => id);
}

function resolveProductAgent(step: StepScopeRow): Readonly<{
  productAgentId: ProductAgentId;
  source: ProductAgentResolutionSource;
}> {
  const assignedAgentId = step.assigned_agent_id?.trim() ?? "";
  if (assignedAgentId && PRODUCT_AGENT_IDS.has(assignedAgentId)) {
    return Object.freeze({
      productAgentId: assignedAgentId as ProductAgentId,
      source: "assigned_product_agent",
    });
  }

  const actionClassId = step.action_class?.trim() ?? "";
  if (!actionClassId) {
    fail(
      "agent_runtime_binding_product_agent_missing",
      `Plan step ${step.step_id} does not name a canonical product agent or a registered action class`,
      "not_found",
      "Assign a canonical product specialist or set the step action class before runtime dispatch.",
    );
  }
  const owners = actionClassOwners(actionClassId);
  if (owners.length === 0) {
    fail(
      "agent_runtime_binding_product_agent_missing",
      `No canonical product agent owns action class ${actionClassId}`,
      "not_found",
      "Register one product-agent owner for the action class before runtime dispatch.",
    );
  }
  if (owners.length > 1) {
    fail(
      "agent_runtime_binding_product_agent_ambiguous",
      `Action class ${actionClassId} has multiple canonical product-agent owners: ${owners.join(", ")}`,
      "state_conflict",
      "Correct the product-agent registry so each represented action class has one owner.",
    );
  }
  return Object.freeze({
    productAgentId: owners[0]!,
    source: "action_class_registry",
  });
}

function assertAssignmentScope(
  assignment: ModelAssignmentRow,
  expected: Readonly<{
    missionId: string;
    runId: string;
    stepId: string | null;
    agentId: ProductAgentId;
  }>,
): void {
  if (
    assignment.mission_id !== expected.missionId
    || assignment.run_id !== expected.runId
    || assignment.step_id !== expected.stepId
    || assignment.agent_id !== expected.agentId
  ) {
    fail(
      "agent_runtime_binding_model_assignment_scope_mismatch",
      `Pinned model assignment ${assignment.id} does not match the resolved mission, run, step, and product agent`,
      "scope_conflict",
      "Pin a model assignment for this exact product agent and canonical run scope.",
    );
  }
}

function compatibleAgentIds(
  configuration: StoredModelConfiguration,
): readonly string[] | null {
  const declared = configuration.capabilities.compatibleAgentIds;
  if (
    !Array.isArray(declared)
    || !declared.every((value) => typeof value === "string" && value.trim().length > 0)
  ) {
    return null;
  }
  return declared;
}

function assertConfigurationSelectable(
  configuration: StoredModelConfiguration,
  role: "primary" | "fallback",
  productAgentId: ProductAgentId,
  options: Readonly<{
    requireEnforcedExecutor: boolean;
    freshnessReferenceMs: number;
    catalogMaximumAgeMs: number;
    catalogMaximumFutureSkewMs: number;
  }>,
): void {
  const unavailableReasons: string[] = [];
  if (configuration.authState !== "authenticated") {
    unavailableReasons.push(`authentication is ${configuration.authState}`);
  }
  if (configuration.healthState !== "healthy") {
    unavailableReasons.push(`health is ${configuration.healthState}`);
  }
  if (configuration.enforcementMode === "unavailable") {
    unavailableReasons.push("enforcement mode is unavailable");
  }
  if (
    options.requireEnforcedExecutor
    && configuration.enforcementMode !== "enforced_executor"
  ) {
    unavailableReasons.push(
      `enforcement mode is ${configuration.enforcementMode.replaceAll("_", " ")}, not enforced executor`,
    );
  }
  if (configuration.disclosureClass === "unavailable") {
    unavailableReasons.push("disclosure classification is unavailable");
  }
  if (
    !configuration.catalogRetrievedAt
    || !Number.isFinite(Date.parse(configuration.catalogRetrievedAt))
  ) {
    unavailableReasons.push("catalog attestation time is invalid");
  } else {
    const observedAt = Date.parse(configuration.catalogRetrievedAt);
    if (
      observedAt
      < options.freshnessReferenceMs - options.catalogMaximumAgeMs
    ) {
      unavailableReasons.push(
        `catalog attestation was older than ${options.catalogMaximumAgeMs} ms when the model assignment was pinned`,
      );
    }
    if (
      observedAt
      > options.freshnessReferenceMs + options.catalogMaximumFutureSkewMs
    ) {
      unavailableReasons.push(
        `catalog attestation was more than ${options.catalogMaximumFutureSkewMs} ms in the future when the model assignment was pinned`,
      );
    }
  }
  if (unavailableReasons.length > 0) {
    fail(
      "agent_runtime_binding_model_configuration_unavailable",
      `Pinned ${role} model configuration ${configuration.id} is unavailable: ${unavailableReasons.join("; ")}`,
      "state_conflict",
      "Choose a live-attested, authenticated, healthy configuration for a future run and pin it before launch.",
    );
  }

  const compatible = compatibleAgentIds(configuration);
  if (!compatible?.includes(productAgentId)) {
    fail(
      "agent_runtime_binding_model_configuration_incompatible",
      `Pinned ${role} model configuration ${configuration.id} is not declared compatible with ${productAgentId}`,
      "policy_denied",
      `Choose a live catalog configuration that explicitly lists ${productAgentId}, then pin it before launch.`,
    );
  }
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value as Readonly<Record<string, unknown>>)) {
    deepFreeze(child);
  }
  return Object.freeze(value);
}

function immutableConfiguration(
  configuration: StoredModelConfiguration,
): StoredModelConfiguration {
  return deepFreeze(structuredClone(configuration));
}

/**
 * Resolves only already-pinned model state for an actual plan step. The
 * service deliberately has no preference-resolution or pinning path: launch
 * must have durably selected the model before execution reaches this boundary.
 */
export class AgentRuntimeBindingService {
  private readonly freshness: Readonly<{
    clock: () => Date;
    catalogMaximumAgeMs: number;
    catalogMaximumFutureSkewMs: number;
  }>;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly modelConfigurations =
      new ModelConfigurationRepository(database),
    options: Readonly<{
      clock?: () => Date;
      catalogMaximumAgeMs?: number;
      catalogMaximumFutureSkewMs?: number;
    }> = {},
  ) {
    const catalogMaximumAgeMs = options.catalogMaximumAgeMs ?? 15 * 60 * 1_000;
    const catalogMaximumFutureSkewMs =
      options.catalogMaximumFutureSkewMs ?? 5_000;
    if (
      !Number.isSafeInteger(catalogMaximumAgeMs)
      || catalogMaximumAgeMs < 1_000
      || catalogMaximumAgeMs > 24 * 60 * 60 * 1_000
    ) throw new RangeError("catalogMaximumAgeMs must be 1000 through 86400000");
    if (
      !Number.isSafeInteger(catalogMaximumFutureSkewMs)
      || catalogMaximumFutureSkewMs < 0
      || catalogMaximumFutureSkewMs > 60_000
    ) throw new RangeError("catalogMaximumFutureSkewMs must be 0 through 60000");
    this.freshness = Object.freeze({
      clock: options.clock ?? (() => new Date()),
      catalogMaximumAgeMs,
      catalogMaximumFutureSkewMs,
    });
  }

  resolve(input: ResolveAgentRuntimeBindingInput): AgentRuntimeBinding {
    const missionId = requiredId(input.missionId, "missionId");
    const runId = requiredId(input.runId, "runId");
    const stepId = requiredId(input.stepId, "stepId");
    const step = this.database.prepare(`
      SELECT
        step.id AS step_id,
        step.run_id AS step_run_id,
        step.assigned_agent_id,
        step.action_class,
        run.mission_id,
        run.journey
      FROM plan_steps step
      JOIN runs run ON run.id = step.run_id
      WHERE step.id = ?
    `).get(stepId) as StepScopeRow | undefined;
    if (!step) {
      fail(
        "agent_runtime_binding_step_not_found",
        `Plan step was not found: ${stepId}`,
        "not_found",
        "Use a canonical plan-step ID from the selected run.",
      );
    }
    if (step.step_run_id !== runId || step.mission_id !== missionId) {
      fail(
        "agent_runtime_binding_scope_mismatch",
        `Plan step ${stepId} does not belong to run ${runId} in mission ${missionId}`,
        "scope_conflict",
        "Use the mission and run IDs that own this canonical plan step.",
      );
    }

    const productAgent = resolveProductAgent(step);
    const { assignment, scope } = this.resolvePinnedAssignment({
      missionId,
      runId,
      stepId,
      productAgentId: productAgent.productAgentId,
    });
    if (step.journey === "autonomous") {
      this.assertAutonomousSignedAssignment({
        missionId,
        runId,
        productAgentId: productAgent.productAgentId,
        assignment,
      });
    }
    const primaryConfiguration = this.configuration(
      assignment.primary_configuration_id,
    );
    const fallbackConfiguration = assignment.fallback_configuration_id
      ? this.configuration(assignment.fallback_configuration_id)
      : null;
    assertConfigurationSelectable(
      primaryConfiguration,
      "primary",
      productAgent.productAgentId,
      this.configurationPolicy(
        step.journey === "autonomous",
        assignment,
      ),
    );
    if (fallbackConfiguration) {
      assertConfigurationSelectable(
        fallbackConfiguration,
        "fallback",
        productAgent.productAgentId,
        this.configurationPolicy(
          step.journey === "autonomous",
          assignment,
        ),
      );
    }

    return deepFreeze({
      schemaVersion: AGENT_RUNTIME_BINDING_SCHEMA_VERSION,
      missionId,
      runId,
      stepId,
      representedActionClassId: step.action_class?.trim() || null,
      productAgentId: productAgent.productAgentId,
      productAgentResolutionSource: productAgent.source,
      modelAssignmentId: assignment.id,
      modelAssignmentScope: scope,
      assignmentResolutionReason: assignment.resolution_reason,
      assignmentResolvedAt: assignment.resolved_at,
      primaryConfigurationId: primaryConfiguration.id,
      fallbackConfigurationId: fallbackConfiguration?.id ?? null,
      primaryConfiguration: immutableConfiguration(primaryConfiguration),
      fallbackConfiguration: fallbackConfiguration
        ? immutableConfiguration(fallbackConfiguration)
        : null,
    } satisfies AgentRuntimeBinding);
  }

  resolveRun(input: Readonly<{
    missionId: string;
    runId: string;
    agentId: ProductAgentId;
  }>): AgentRunRuntimeBinding {
    const missionId = requiredId(input.missionId, "missionId");
    const runId = requiredId(input.runId, "runId");
    const agentId = requiredId(input.agentId, "agentId") as ProductAgentId;
    if (!PRODUCT_AGENT_IDS.has(agentId)) {
      fail(
        "agent_runtime_binding_product_agent_missing",
        `Run model binding names an unknown product agent: ${agentId}`,
        "not_found",
        "Use one canonical product specialist from the live agent registry.",
      );
    }
    const run = this.database.prepare(`
      SELECT mission_id, journey FROM runs WHERE id = ?
    `).get(runId) as { mission_id: string; journey: string } | undefined;
    if (!run || run.mission_id !== missionId) {
      fail(
        "agent_runtime_binding_scope_mismatch",
        `Run ${runId} does not belong to mission ${missionId}`,
        "scope_conflict",
        "Use the mission ID that owns this canonical run.",
      );
    }
    const { assignment } = this.resolvePinnedAssignment({
      missionId,
      runId,
      stepId: null,
      productAgentId: agentId,
    });
    if (run.journey === "autonomous") {
      this.assertAutonomousSignedAssignment({
        missionId,
        runId,
        productAgentId: agentId,
        assignment,
      });
    }
    const primaryConfiguration = this.configuration(
      assignment.primary_configuration_id,
    );
    const fallbackConfiguration = assignment.fallback_configuration_id
      ? this.configuration(assignment.fallback_configuration_id)
      : null;
    const policy = this.configurationPolicy(
      run.journey === "autonomous",
      assignment,
    );
    assertConfigurationSelectable(primaryConfiguration, "primary", agentId, policy);
    if (fallbackConfiguration) {
      assertConfigurationSelectable(fallbackConfiguration, "fallback", agentId, policy);
    }
    return deepFreeze({
      schemaVersion: AGENT_RUNTIME_BINDING_SCHEMA_VERSION,
      missionId,
      runId,
      stepId: null,
      representedActionClassId: null,
      productAgentId: agentId,
      productAgentResolutionSource: "explicit_run_agent",
      modelAssignmentId: assignment.id,
      modelAssignmentScope: "run",
      assignmentResolutionReason: assignment.resolution_reason,
      assignmentResolvedAt: assignment.resolved_at,
      primaryConfigurationId: primaryConfiguration.id,
      fallbackConfigurationId: fallbackConfiguration?.id ?? null,
      primaryConfiguration: immutableConfiguration(primaryConfiguration),
      fallbackConfiguration: fallbackConfiguration
        ? immutableConfiguration(fallbackConfiguration)
        : null,
    } satisfies AgentRunRuntimeBinding);
  }

  private configurationPolicy(
    requireEnforcedExecutor: boolean,
    assignment: Pick<ModelAssignmentRow, "id" | "resolved_at">,
  ): Readonly<{
    requireEnforcedExecutor: boolean;
    freshnessReferenceMs: number;
    catalogMaximumAgeMs: number;
    catalogMaximumFutureSkewMs: number;
  }> {
    const nowMs = this.freshness.clock().getTime();
    if (!Number.isFinite(nowMs)) {
      throw new RangeError("Agent runtime model-binding clock returned an invalid date");
    }
    const freshnessReferenceMs = Date.parse(assignment.resolved_at);
    if (
      !Number.isFinite(freshnessReferenceMs)
      || freshnessReferenceMs
        > nowMs + this.freshness.catalogMaximumFutureSkewMs
    ) {
      fail(
        "agent_runtime_binding_model_configuration_unavailable",
        `Pinned model assignment ${assignment.id} has an invalid or future-dated resolution receipt`,
        "state_conflict",
        "Keep the run stopped and create a new reviewed run with a valid launch-time model-assignment receipt.",
      );
    }
    return {
      requireEnforcedExecutor,
      freshnessReferenceMs,
      catalogMaximumAgeMs: this.freshness.catalogMaximumAgeMs,
      catalogMaximumFutureSkewMs: this.freshness.catalogMaximumFutureSkewMs,
    };
  }

  private configuration(id: string): StoredModelConfiguration {
    try {
      return this.modelConfigurations.getConfiguration(id);
    } catch (error) {
      if (!(error instanceof ModelConfigurationError)) throw error;
      fail(
        "agent_runtime_binding_model_configuration_missing",
        `Pinned model configuration could not be loaded: ${id}`,
        "not_found",
        "Repair the immutable model-assignment reference before runtime dispatch.",
      );
    }
  }

  private assertAutonomousSignedAssignment(input: Readonly<{
    missionId: string;
    runId: string;
    productAgentId: ProductAgentId;
    assignment: ModelAssignmentRow;
  }>): void {
    const row = this.database.prepare(`
      SELECT
        run.mission_id AS run_mission_id,
        run.contract_id,
        run.contract_version_bound,
        run.contract_hash_bound,
        contract.mission_id AS contract_mission_id,
        contract.version AS contract_version,
        contract.state AS contract_state,
        contract.contract_hash,
        contract.action_policy_json
      FROM runs run
      LEFT JOIN mission_contracts contract ON contract.id = run.contract_id
      WHERE run.id = ?
    `).get(input.runId) as AutonomousContractAssignmentRow | undefined;
    const mismatch = (detail: string): never => fail(
      "agent_runtime_binding_signed_assignment_mismatch",
      `Run ${input.runId} model assignment for ${input.productAgentId} does not match the signed Autonomous contract: ${detail}`,
      "policy_denied",
      "Keep the run stopped and create a new reviewed run from one exact signed model-assignment set.",
    );
    const contractRow = row
      ?? mismatch("the bound confirmed contract lineage is missing or inconsistent");
    if (
      contractRow.run_mission_id !== input.missionId
      || !contractRow.contract_id
      || contractRow.contract_mission_id !== input.missionId
      || contractRow.contract_state !== "confirmed"
      || contractRow.contract_version_bound === null
      || contractRow.contract_hash_bound === null
      || contractRow.contract_version !== contractRow.contract_version_bound
      || contractRow.contract_hash !== contractRow.contract_hash_bound
      || !contractRow.action_policy_json
    ) {
      mismatch("the bound confirmed contract lineage is missing or inconsistent");
    }
    if (input.assignment.step_id !== null) {
      mismatch("Autonomous execution requires the immutable run-level assignment");
    }

    let policy: unknown;
    const actionPolicyJson = contractRow.action_policy_json
      ?? mismatch("the signed action policy is missing");
    try {
      policy = JSON.parse(actionPolicyJson);
    } catch {
      mismatch("the signed action policy is not valid JSON");
    }
    if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
      mismatch("the signed action policy is not an object");
    }
    const record = policy as Readonly<Record<string, unknown>>;
    const specialists = record.specialistAgentIds;
    if (
      !Array.isArray(specialists)
      || !specialists.every((value) =>
        typeof value === "string" && value.trim().length > 0)
      || !specialists.includes(input.productAgentId)
    ) {
      mismatch("the product agent is absent from the signed specialist set");
    }
    const assignmentValues: readonly unknown[] = Array.isArray(
      record.agentModelAssignments,
    )
      ? record.agentModelAssignments as readonly unknown[]
      : mismatch("the signed model-assignment set is missing");
    const validSelection = (
      value: unknown,
    ): value is Readonly<{
      agentId: string;
      primaryConfigurationId: string;
      fallbackConfigurationId: string | null;
      source?: string;
    }> => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return false;
      const selection = value as Readonly<Record<string, unknown>>;
      const keys = Object.keys(selection).sort();
      const expected = selection.source === undefined
        ? ["agentId", "fallbackConfigurationId", "primaryConfigurationId"]
        : ["agentId", "fallbackConfigurationId", "primaryConfigurationId", "source"];
      return keys.length === expected.length
        && keys.every((key, index) => key === expected[index])
        && typeof selection.agentId === "string"
        && selection.agentId.trim().length > 0
        && typeof selection.primaryConfigurationId === "string"
        && selection.primaryConfigurationId.trim().length > 0
        && (
          selection.fallbackConfigurationId === null
          || (
            typeof selection.fallbackConfigurationId === "string"
            && selection.fallbackConfigurationId.trim().length > 0
          )
        )
        && (
          selection.source === undefined
          || ["recommended", "inherited", "operator_override"].includes(
            String(selection.source),
          )
        );
    };
    const assignments = assignmentValues.filter(validSelection);
    if (assignments.length !== assignmentValues.length) {
      mismatch("the signed model-assignment set is malformed");
    }
    const matches = assignments.filter(
      (selection) => selection.agentId === input.productAgentId,
    );
    if (matches.length !== 1) {
      mismatch("the signed model-assignment set is missing or ambiguous for the product agent");
    }
    const signed = matches[0]!;
    if (
      input.assignment.primary_configuration_id !== signed.primaryConfigurationId
      || input.assignment.fallback_configuration_id
        !== signed.fallbackConfigurationId
    ) {
      mismatch("the pinned primary or fallback configuration ID drifted");
    }
  }

  private resolvePinnedAssignment(input: Readonly<{
    missionId: string;
    runId: string;
    stepId: string | null;
    productAgentId: ProductAgentId;
  }>): Readonly<{
    assignment: ModelAssignmentRow;
    scope: ModelAssignmentBindingScope;
  }> {
    const stepAssignments = input.stepId === null ? [] : this.database.prepare(`
      SELECT
        id, agent_id, mission_id, run_id, step_id,
        primary_configuration_id, fallback_configuration_id,
        resolution_reason, resolved_at
      FROM agent_model_assignments
      WHERE step_id = ?
        AND assignment_purpose = 'execution'
        AND pinned = 1
      ORDER BY created_at, id
    `).all(input.stepId) as ModelAssignmentRow[];
    if (stepAssignments.length > 1) {
      fail(
        "agent_runtime_binding_model_assignment_ambiguous",
        `Plan step ${input.stepId!} has ${stepAssignments.length} pinned model assignments`,
        "state_conflict",
        "Reconcile the duplicate step-level assignment records before runtime dispatch.",
      );
    }
    if (input.stepId !== null && stepAssignments.length === 1) {
      const assignment = stepAssignments[0]!;
      assertAssignmentScope(assignment, {
        missionId: input.missionId,
        runId: input.runId,
        stepId: input.stepId,
        agentId: input.productAgentId,
      });
      return Object.freeze({ assignment, scope: "step" });
    }

    const runAssignments = this.database.prepare(`
      SELECT
        id, agent_id, mission_id, run_id, step_id,
        primary_configuration_id, fallback_configuration_id,
        resolution_reason, resolved_at
      FROM agent_model_assignments
      WHERE run_id = ?
        AND step_id IS NULL
        AND agent_id = ?
        AND assignment_purpose = 'execution'
        AND pinned = 1
      ORDER BY created_at, id
    `).all(input.runId, input.productAgentId) as ModelAssignmentRow[];
    if (runAssignments.length > 1) {
      fail(
        "agent_runtime_binding_model_assignment_ambiguous",
        `Run ${input.runId} has ${runAssignments.length} pinned model assignments for ${input.productAgentId}`,
        "state_conflict",
        "Reconcile the duplicate run-level assignment records before runtime dispatch.",
      );
    }
    if (runAssignments.length === 0) {
      fail(
        "agent_runtime_binding_model_assignment_missing",
        `No pinned step or run model assignment exists for ${input.productAgentId} on step ${input.stepId}`,
        "not_found",
        "Resolve and pin this product agent's model configuration before launching the run.",
      );
    }
    const assignment = runAssignments[0]!;
    assertAssignmentScope(assignment, {
      missionId: input.missionId,
      runId: input.runId,
      stepId: null,
      agentId: input.productAgentId,
    });
    return Object.freeze({ assignment, scope: "run" });
  }
}

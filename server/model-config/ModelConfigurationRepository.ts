import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  modelConfigurationConflict,
  modelConfigurationNotFound,
  modelConfigurationScopeConflict,
} from "./ModelConfigurationError";
import type {
  ExactPinModelAssignmentInput,
  ModelAssignmentPreference,
  ModelCatalogItem,
  ModelAssignmentPurpose,
  ModelPreferenceFilters,
  ModelPreferenceScopeType,
  PinModelAssignmentInput,
  PinnedModelAssignment,
  PutModelPreferenceInput,
  StoredModelConfiguration,
} from "./types";

interface ConfigurationRow {
  readonly id: string;
  readonly provider_id: string;
  readonly model_id: string;
  readonly reasoning_effort: string | null;
  readonly context_policy_json: string;
  readonly capabilities_json: string;
  readonly context_limit: number | null;
  readonly cost_class: StoredModelConfiguration["costClass"];
  readonly latency_class: StoredModelConfiguration["latencyClass"];
  readonly disclosure_class: StoredModelConfiguration["disclosureClass"];
  readonly enforcement_mode: "enforced" | "observe_only" | "advisory_only" | "unavailable";
  readonly auth_state: "healthy" | "missing" | "expired" | "degraded" | "unknown";
  readonly health_state: "healthy" | "degraded" | "offline" | "unknown";
  readonly catalog_source: string;
  readonly catalog_retrieved_at: string;
  readonly configuration_source: StoredModelConfiguration["configurationSource"];
  readonly created_at: string;
  readonly updated_at: string;
  readonly version: number;
}

interface PreferenceRow {
  readonly id: string;
  readonly scope_type: ModelPreferenceScopeType;
  readonly scope_id: string;
  readonly agent_id: string | null;
  readonly primary_configuration_id: string;
  readonly fallback_configuration_id: string | null;
  readonly resolution_reason: string;
  readonly version: number;
  readonly created_by: string;
  readonly created_at: string;
}

interface AssignmentRow {
  readonly id: string;
  readonly agent_id: string;
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly assignment_purpose: ModelAssignmentPurpose;
  readonly primary_configuration_id: string;
  readonly fallback_configuration_id: string | null;
  readonly inheritance_level: ModelPreferenceScopeType;
  readonly pinned: 0 | 1;
  readonly resolution_reason: string;
  readonly resolved_at: string;
  readonly created_at: string;
}

interface ScopeLineage {
  readonly missionId: string | null;
  readonly runId: string | null;
  readonly stepId: string | null;
}

function objectJson(value: string, label: string): Readonly<Record<string, unknown>> {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} is not a JSON object`);
  }
  return parsed as Readonly<Record<string, unknown>>;
}

function configuration(row: ConfigurationRow): StoredModelConfiguration {
  const capabilities = objectJson(row.capabilities_json, "model capabilities");
  return {
    id: row.id,
    providerId: row.provider_id,
    modelId: row.model_id,
    displayName: typeof capabilities.displayName === "string"
      ? capabilities.displayName
      : row.model_id,
    executionBoundary: capabilities.executionBoundary
      === "local_deterministic_policy"
      ? "local_deterministic_policy"
      : "provider_tool_calling",
    reasoningEffort: row.reasoning_effort,
    contextPolicy: objectJson(row.context_policy_json, "model context policy"),
    capabilities,
    contextLimit: row.context_limit,
    costClass: row.cost_class,
    latencyClass: row.latency_class,
    disclosureClass: row.disclosure_class,
    enforcementMode: row.enforcement_mode === "enforced"
      ? "enforced_executor"
      : row.enforcement_mode === "observe_only"
        ? "observe_only_executor"
        : row.enforcement_mode === "advisory_only"
          ? "advisor_only"
          : "unavailable",
    authState: row.auth_state === "healthy"
      ? "authenticated"
      : row.auth_state === "missing"
        ? "unconfigured"
        : row.auth_state === "expired"
          ? "invalid"
          : row.auth_state === "degraded"
            ? "invalid"
            : "unknown",
    healthState: row.health_state === "healthy"
      ? "healthy"
      : row.health_state === "degraded"
        ? "degraded"
        : row.health_state === "offline"
          ? "unavailable"
          : "unknown",
    catalogSource: row.catalog_source,
    catalogRetrievedAt: row.catalog_retrieved_at,
    configurationSource: row.configuration_source,
    version: row.version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function preference(row: PreferenceRow): ModelAssignmentPreference {
  return {
    id: row.id,
    scopeType: row.scope_type,
    scopeId: row.scope_id,
    agentId: row.agent_id,
    primaryConfigurationId: row.primary_configuration_id,
    fallbackConfigurationId: row.fallback_configuration_id,
    resolutionReason: row.resolution_reason,
    version: row.version,
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedBy: row.created_by,
    updatedAt: row.created_at,
  };
}

function assignment(row: AssignmentRow): PinnedModelAssignment {
  return {
    id: row.id,
    agentId: row.agent_id,
    missionId: row.mission_id,
    runId: row.run_id,
    stepId: row.step_id,
    purpose: row.assignment_purpose,
    primaryConfigurationId: row.primary_configuration_id,
    fallbackConfigurationId: row.fallback_configuration_id,
    inheritanceLevel: row.inheritance_level,
    pinned: true,
    resolutionReason: row.resolution_reason,
    resolvedAt: row.resolved_at,
    createdAt: row.created_at,
  };
}

const CONFIGURATION_SELECT = `
  SELECT id, provider_id, model_id, reasoning_effort, context_policy_json,
    capabilities_json, context_limit, cost_class, latency_class,
    disclosure_class, enforcement_mode, auth_state, health_state,
    catalog_source, catalog_retrieved_at, configuration_source,
    created_at, updated_at, version
  FROM model_configurations
`;

const PREFERENCE_SELECT = `
  SELECT id, scope_type, scope_id, agent_id, primary_configuration_id,
    fallback_configuration_id, resolution_reason, version, created_by, created_at
  FROM model_assignment_preferences
`;

const ASSIGNMENT_SELECT = `
  SELECT id, agent_id, mission_id, run_id, step_id, assignment_purpose,
    primary_configuration_id, fallback_configuration_id,
    inheritance_level, pinned, resolution_reason, resolved_at, created_at
  FROM agent_model_assignments
`;

export class ModelConfigurationRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  listConfigurations(ids?: readonly string[]): StoredModelConfiguration[] {
    if (ids && ids.length === 0) return [];
    const rows = ids
      ? this.database.prepare(
          `${CONFIGURATION_SELECT} WHERE id IN (${ids.map(() => "?").join(", ")})
           ORDER BY provider_id, model_id, reasoning_effort, version`,
        ).all(...ids) as ConfigurationRow[]
      : this.database.prepare(
          `${CONFIGURATION_SELECT}
           ORDER BY provider_id, model_id, reasoning_effort, version`,
        ).all() as ConfigurationRow[];
    return rows.map(configuration);
  }

  getConfiguration(id: string): StoredModelConfiguration {
    const row = this.database.prepare(`${CONFIGURATION_SELECT} WHERE id = ?`)
      .get(id) as ConfigurationRow | undefined;
    if (!row) {
      throw modelConfigurationNotFound(
        "model_configuration_not_found",
        `Model configuration was not found: ${id}`,
        "Refresh the live model catalog and select an available configuration.",
      );
    }
    return configuration(row);
  }

  findConfiguration(id: string): StoredModelConfiguration | null {
    const row = this.database.prepare(`${CONFIGURATION_SELECT} WHERE id = ?`)
      .get(id) as ConfigurationRow | undefined;
    return row ? configuration(row) : null;
  }

  materializeCatalogConfiguration(item: ModelCatalogItem): StoredModelConfiguration {
    return inImmediateTransaction(this.database, () => {
      const existing = this.database.prepare(`${CONFIGURATION_SELECT} WHERE id = ?`)
        .get(item.configurationId) as ConfigurationRow | undefined;
      if (existing) return configuration(existing);
      const versionRow = this.database.prepare(`
        SELECT COALESCE(MAX(version), 0) + 1 AS next_version
        FROM model_configurations
        WHERE provider_id = ? AND model_id = ?
      `).get(item.providerId, item.modelId) as { readonly next_version: number };
      const now = this.clock().toISOString();
      const enforcementMode = item.enforcementMode === "enforced_executor"
        ? "enforced"
        : item.enforcementMode === "observe_only_executor"
          ? "observe_only"
          : item.enforcementMode === "advisor_only"
            ? "advisory_only"
            : "unavailable";
      const authState = item.authState === "authenticated"
        ? "healthy"
        : item.authState === "unconfigured"
          ? "missing"
          : item.authState === "invalid"
            ? "degraded"
            : "unknown";
      const healthState = item.healthState === "healthy"
        ? "healthy"
        : item.healthState === "degraded"
          ? "degraded"
          : item.healthState === "unavailable"
            ? "offline"
            : "unknown";
      this.database.prepare(`
        INSERT INTO model_configurations (
          id, provider_id, model_id, returned_model_id, reasoning_effort,
          context_policy_json, capabilities_json, context_limit,
          cost_class, latency_class, disclosure_class, enforcement_mode,
          auth_state, health_state, catalog_source, catalog_retrieved_at,
          configuration_source, prompt_template_hash,
          created_at, updated_at, version
        ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', NULL, ?, ?, ?)
      `).run(
        item.configurationId,
        item.providerId,
        item.modelId,
        item.reasoningEffort,
        JSON.stringify({
          source: "runtime_attested_default",
          maximumContextTokens: item.contextLimit,
        }),
        JSON.stringify({
          displayName: item.displayName,
          executionBoundary: item.executionBoundary,
          toolCalling: item.capabilities.toolCalling,
          structuredOutput: item.capabilities.structuredOutput,
          compatibleActionClassIds: item.capabilities.compatibleActionClassIds,
          compatibleAgentIds: item.compatibleAgentIds,
          supportedReasoningEfforts: item.supportedReasoningEfforts,
          localDeterministicActionClassIdsByAgent:
            item.capabilities.localDeterministicActionClassIdsByAgent,
        }),
        item.contextLimit,
        item.costClass,
        item.latencyClass,
        item.disclosureClass,
        enforcementMode,
        authState,
        healthState,
        item.catalogSource,
        item.catalogRetrievedAt ?? now,
        now,
        now,
        versionRow.next_version,
      );
      return this.getConfiguration(item.configurationId);
    });
  }

  listPreferences(filters: ModelPreferenceFilters = {}): ModelAssignmentPreference[] {
    const clauses = ["is_current = 1"];
    const values: string[] = [];
    if (filters.scopeType) {
      clauses.push("scope_type = ?");
      values.push(filters.scopeType);
    }
    if (filters.scopeId) {
      clauses.push("scope_id = ?");
      values.push(filters.scopeId);
    }
    if (filters.agentId) {
      clauses.push("agent_id = ?");
      values.push(filters.agentId);
    }
    const rows = this.database.prepare(`
      ${PREFERENCE_SELECT}
      WHERE ${clauses.join(" AND ")}
      ORDER BY scope_type, scope_id, agent_id, version DESC
    `).all(...values) as PreferenceRow[];
    return rows.map(preference);
  }

  getCurrentPreference(
    scopeType: ModelPreferenceScopeType,
    scopeId: string,
    agentId: string | null,
  ): ModelAssignmentPreference | null {
    const row = this.database.prepare(`
      ${PREFERENCE_SELECT}
      WHERE scope_type = ? AND scope_id = ?
        AND agent_id IS ?
        AND is_current = 1
    `).get(scopeType, scopeId, agentId) as PreferenceRow | undefined;
    return row ? preference(row) : null;
  }

  putPreference(
    input: PutModelPreferenceInput,
    actorId: string,
  ): ModelAssignmentPreference {
    return inImmediateTransaction(this.database, () => {
      const lineage = this.scopeLineage(
        input.scopeType,
        input.scopeId,
        input.agentId,
      );
      this.getConfiguration(input.primaryConfigurationId);
      if (input.fallbackConfigurationId) {
        this.getConfiguration(input.fallbackConfigurationId);
      }
      const current = this.getCurrentPreference(
        input.scopeType,
        input.scopeId,
        input.agentId,
      );
      const actualVersion = current?.version ?? 0;
      if (actualVersion !== input.expectedVersion) {
        throw modelConfigurationConflict(
          "model_preference_version_conflict",
          `Model preference changed: expected version ${input.expectedVersion}, current version ${actualVersion}`,
          "Reload the current preference, review the resolved configuration, and retry with its exact version.",
        );
      }
      const now = this.clock().toISOString();
      const id = `modelpref_${randomUUID()}`;
      this.database.prepare(`
        INSERT INTO model_assignment_preferences (
          id, scope_type, scope_id, agent_id, mission_id, run_id, step_id,
          primary_configuration_id, fallback_configuration_id,
          version, active, is_current, supersedes_preference_id,
          resolution_reason, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?)
      `).run(
        id,
        input.scopeType,
        input.scopeId,
        input.agentId,
        lineage.missionId,
        lineage.runId,
        lineage.stepId,
        input.primaryConfigurationId,
        input.fallbackConfigurationId,
        actualVersion + 1,
        current?.id ?? null,
        input.reason,
        actorId,
        now,
      );
      const created = this.getCurrentPreference(
        input.scopeType,
        input.scopeId,
        input.agentId,
      );
      if (!created || created.id !== id) {
        throw new Error("Model preference was not committed as the current version");
      }
      return created;
    });
  }

  resolvePreference(
    agentId: string,
    context: ScopeLineage,
  ): ModelAssignmentPreference | null {
    this.assertAgent(agentId);
    this.validateContext(context);
    const candidates: readonly [
      ModelPreferenceScopeType,
      string | null,
      string | null,
    ][] = [
      ["step", context.stepId, agentId],
      ["run", context.runId, agentId],
      ["mission", context.missionId, agentId],
      ["agent", agentId, agentId],
      ["global", "global", null],
    ];
    for (const [scopeType, scopeId, preferenceAgentId] of candidates) {
      if (!scopeId) continue;
      const current = this.getCurrentPreference(
        scopeType,
        scopeId,
        preferenceAgentId,
      );
      if (current) return current;
    }
    return null;
  }

  findPinnedAssignment(input: PinModelAssignmentInput): PinnedModelAssignment | null {
    const row = this.database.prepare(`
      ${ASSIGNMENT_SELECT}
      WHERE agent_id = ?
        AND mission_id IS ?
        AND run_id IS ?
        AND step_id IS ?
        AND assignment_purpose = ?
        AND pinned = 1
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `).get(
      input.agentId,
      input.missionId ?? null,
      input.runId ?? null,
      input.stepId ?? null,
      input.purpose ?? "execution",
    ) as AssignmentRow | undefined;
    return row ? assignment(row) : null;
  }

  listPinnedAssignmentsForRun(runId: string): PinnedModelAssignment[] {
    if (!this.database.prepare("SELECT 1 FROM runs WHERE id = ?").get(runId)) {
      throw modelConfigurationNotFound(
        "model_configuration_run_not_found",
        `Run was not found: ${runId}`,
        "Use a canonical run ID from the selected mission.",
      );
    }
    const rows = this.database.prepare(`
      ${ASSIGNMENT_SELECT}
      WHERE run_id = ? AND pinned = 1
      ORDER BY assignment_purpose, agent_id, step_id, created_at, id
    `).all(runId) as AssignmentRow[];
    return rows.map(assignment);
  }

  createPinnedAssignment(
    input: PinModelAssignmentInput,
    preferenceValue: ModelAssignmentPreference,
  ): PinnedModelAssignment {
    return inImmediateTransaction(this.database, () => {
      const existing = this.findPinnedAssignment(input);
      if (existing) return existing;
      const context: ScopeLineage = {
        missionId: input.missionId ?? null,
        runId: input.runId ?? null,
        stepId: input.stepId ?? null,
      };
      this.assertAgent(input.agentId);
      this.validateContext(context);
      const now = this.clock().toISOString();
      const id = `modelassign_${randomUUID()}`;
      this.database.prepare(`
        INSERT INTO agent_model_assignments (
          id, agent_id, mission_id, run_id, step_id,
          assignment_purpose,
          primary_configuration_id, fallback_configuration_id,
          inheritance_level, pinned, resolution_reason,
          resolved_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
      `).run(
        id,
        input.agentId,
        context.missionId,
        context.runId,
        context.stepId,
        input.purpose ?? "execution",
        preferenceValue.primaryConfigurationId,
        preferenceValue.fallbackConfigurationId,
        preferenceValue.scopeType,
        input.resolutionReason
          ?? `Pinned from ${preferenceValue.scopeType} preference ${preferenceValue.id} version ${preferenceValue.version}`,
        now,
        now,
      );
      const row = this.database.prepare(`${ASSIGNMENT_SELECT} WHERE id = ?`)
        .get(id) as AssignmentRow | undefined;
      if (!row || row.pinned !== 1) {
        throw new Error("Pinned agent model assignment was not committed");
      }
      return assignment(row);
    });
  }

  /**
   * Pins an exact operator-reviewed catalog selection without creating or
   * consulting a mutable preference. The surrounding mission/branch
   * transaction remains authoritative; this method is safe when nested in it.
   */
  createExactPinnedAssignment(
    input: ExactPinModelAssignmentInput,
  ): PinnedModelAssignment {
    return inImmediateTransaction(this.database, () => {
      const existing = this.findPinnedAssignment(input);
      if (existing) {
        if (
          existing.primaryConfigurationId !== input.primaryConfigurationId
          || existing.fallbackConfigurationId !== input.fallbackConfigurationId
        ) {
          throw modelConfigurationConflict(
            "model_assignment_pin_conflict",
            `A different model configuration is already pinned for ${input.agentId} in this exact mission/run/step scope`,
            "Use the existing immutable assignment, or create a new reviewed run with the intended model configuration.",
          );
        }
        return existing;
      }
      const context: ScopeLineage = {
        missionId: input.missionId ?? null,
        runId: input.runId ?? null,
        stepId: input.stepId ?? null,
      };
      this.assertAgent(input.agentId);
      this.validateContext(context);
      this.getConfiguration(input.primaryConfigurationId);
      if (input.fallbackConfigurationId) {
        this.getConfiguration(input.fallbackConfigurationId);
      }
      const now = this.clock().toISOString();
      const id = `modelassign_${randomUUID()}`;
      this.database.prepare(`
        INSERT INTO agent_model_assignments (
          id, agent_id, mission_id, run_id, step_id,
          assignment_purpose,
          primary_configuration_id, fallback_configuration_id,
          inheritance_level, pinned, resolution_reason,
          resolved_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
      `).run(
        id,
        input.agentId,
        context.missionId,
        context.runId,
        context.stepId,
        input.purpose ?? "execution",
        input.primaryConfigurationId,
        input.fallbackConfigurationId,
        input.inheritanceLevel ?? "mission",
        input.resolutionReason
          ?? "Pinned from the exact operator-reviewed Autonomous mission contract",
        now,
        now,
      );
      const row = this.database.prepare(`${ASSIGNMENT_SELECT} WHERE id = ?`)
        .get(id) as AssignmentRow | undefined;
      if (!row || row.pinned !== 1) {
        throw new Error("Exact pinned agent model assignment was not committed");
      }
      return assignment(row);
    });
  }

  private assertAgent(agentId: string): void {
    if (!this.database.prepare("SELECT 1 FROM agents WHERE id = ?").get(agentId)) {
      throw modelConfigurationNotFound(
        "model_configuration_agent_not_found",
        `Agent was not found: ${agentId}`,
        "Refresh the live agent fleet and select a current stable agent ID.",
      );
    }
  }

  private scopeLineage(
    scopeType: ModelPreferenceScopeType,
    scopeId: string,
    agentId: string | null,
  ): ScopeLineage {
    if (scopeType === "global") {
      if (scopeId !== "global" || agentId !== null) {
        throw modelConfigurationScopeConflict(
          "Global model preference must use scopeId global and no agentId",
        );
      }
      return { missionId: null, runId: null, stepId: null };
    }
    if (!agentId) {
      throw modelConfigurationScopeConflict(
        `${scopeType} model preference requires an exact agent`,
      );
    }
    this.assertAgent(agentId);
    if (scopeType === "agent") {
      if (scopeId !== agentId) {
        throw modelConfigurationScopeConflict(
          "Agent model preference scopeId must equal agentId",
        );
      }
      return { missionId: null, runId: null, stepId: null };
    }
    if (scopeType === "mission") {
      if (!this.database.prepare("SELECT 1 FROM missions WHERE id = ?").get(scopeId)) {
        throw modelConfigurationNotFound(
          "model_configuration_mission_not_found",
          `Mission was not found: ${scopeId}`,
          "Use a canonical mission ID from the current mission portfolio.",
        );
      }
      return { missionId: scopeId, runId: null, stepId: null };
    }
    if (scopeType === "run") {
      const row = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?")
        .get(scopeId) as { readonly mission_id: string } | undefined;
      if (!row) {
        throw modelConfigurationNotFound(
          "model_configuration_run_not_found",
          `Run was not found: ${scopeId}`,
          "Use a canonical run ID from the selected mission.",
        );
      }
      return { missionId: row.mission_id, runId: scopeId, stepId: null };
    }
    const row = this.database.prepare(`
      SELECT r.mission_id, s.run_id
      FROM plan_steps s
      JOIN runs r ON r.id = s.run_id
      WHERE s.id = ?
    `).get(scopeId) as {
      readonly mission_id: string;
      readonly run_id: string;
    } | undefined;
    if (!row) {
      throw modelConfigurationNotFound(
        "model_configuration_step_not_found",
        `Plan step was not found: ${scopeId}`,
        "Use a canonical step ID from the selected run plan.",
      );
    }
    return {
      missionId: row.mission_id,
      runId: row.run_id,
      stepId: scopeId,
    };
  }

  private validateContext(context: ScopeLineage): void {
    if (context.stepId && !context.runId) {
      throw modelConfigurationScopeConflict(
        "Step-level model resolution requires its runId",
      );
    }
    if (context.runId && !context.missionId) {
      throw modelConfigurationScopeConflict(
        "Run-level model resolution requires its missionId",
      );
    }
    if (context.missionId && !this.database.prepare(
      "SELECT 1 FROM missions WHERE id = ?",
    ).get(context.missionId)) {
      throw modelConfigurationNotFound(
        "model_configuration_mission_not_found",
        `Mission was not found: ${context.missionId}`,
        "Use a canonical mission ID from the current mission portfolio.",
      );
    }
    if (context.runId) {
      const run = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?")
        .get(context.runId) as { readonly mission_id: string } | undefined;
      if (!run) {
        throw modelConfigurationNotFound(
          "model_configuration_run_not_found",
          `Run was not found: ${context.runId}`,
          "Use a canonical run ID from the selected mission.",
        );
      }
      if (run.mission_id !== context.missionId) {
        throw modelConfigurationScopeConflict(
          "Run does not belong to the supplied mission",
        );
      }
    }
    if (context.stepId) {
      const step = this.database.prepare("SELECT run_id FROM plan_steps WHERE id = ?")
        .get(context.stepId) as { readonly run_id: string } | undefined;
      if (!step) {
        throw modelConfigurationNotFound(
          "model_configuration_step_not_found",
          `Plan step was not found: ${context.stepId}`,
          "Use a canonical step ID from the selected run plan.",
        );
      }
      if (step.run_id !== context.runId) {
        throw modelConfigurationScopeConflict(
          "Step does not belong to the supplied run",
        );
      }
    }
  }
}

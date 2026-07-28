import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  AutonomousAgentModelAssignmentReceipt,
} from "../../../src/domain/types/commandOs";
import type {
  ModelCatalog,
  ModelCatalogItem,
} from "../../../src/domain/types/modelConfiguration";
import { MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS } from "../../../src/data/api/modelConfiguration";
import { MissionAgentModelAssignments } from "../../../src/features/missions/MissionAgentModelAssignments";
import {
  assignmentForAgent,
  configurationSelectableForAgent,
  exactAssignmentFromReceipt,
  filterAgentModelAssignments,
  preferredConfigurationForModel,
  upsertAgentModelAssignment,
} from "../../../src/features/missions/missionModelAssignmentState";

const OBSERVED_AT = "2026-07-26T12:00:00.000Z";

function catalogItem(input: Partial<ModelCatalogItem> & {
  readonly configurationId: string;
  readonly modelId: string;
  readonly reasoningEffort: string | null;
}): ModelCatalogItem {
  return {
    configurationId: input.configurationId,
    providerId: input.providerId ?? "provider-live",
    modelId: input.modelId,
    displayName: input.displayName ?? input.modelId,
    executionBoundary: input.executionBoundary ?? "provider_tool_calling",
    reasoningEffort: input.reasoningEffort,
    supportedReasoningEfforts: ["low", "high"],
    contextLimit: input.contextLimit ?? 128_000,
    costClass: input.costClass ?? "standard",
    latencyClass: input.latencyClass ?? "fast",
    disclosureClass: input.disclosureClass ?? "sanitized_internal",
    enforcementMode: input.enforcementMode ?? "enforced_executor",
    authState: input.authState ?? "authenticated",
    healthState: input.healthState ?? "healthy",
    catalogSource: input.catalogSource ?? "unit-live-catalog",
    catalogRetrievedAt: input.catalogRetrievedAt ?? OBSERVED_AT,
    capabilities: input.capabilities ?? {
      toolCalling: true,
      structuredOutput: true,
      compatibleActionClassIds: ["active_host_discovery"],
      localDeterministicActionClassIdsByAgent: {},
    },
    compatibleAgentIds: input.compatibleAgentIds ?? ["ReconScout"],
    selectable: input.selectable ?? true,
    unavailableReasons: input.unavailableReasons ?? [],
  };
}

const primaryLow = catalogItem({
  configurationId: "configuration-primary-low",
  modelId: "model-primary",
  displayName: "Primary Model",
  executionBoundary: "local_deterministic_policy",
  reasoningEffort: "low",
  capabilities: {
    toolCalling: false,
    structuredOutput: true,
    compatibleActionClassIds: ["active_host_discovery"],
    localDeterministicActionClassIdsByAgent: {
      ReconScout: ["active_host_discovery"],
    },
  },
});
const primaryHigh = catalogItem({
  configurationId: "configuration-primary-high",
  modelId: "model-primary",
  displayName: "Primary Model",
  reasoningEffort: "high",
});
const fallbackLow = catalogItem({
  configurationId: "configuration-fallback-low",
  providerId: "provider-fallback",
  modelId: "model-fallback",
  displayName: "Fallback Model",
  reasoningEffort: "low",
});
const fallbackHigh = catalogItem({
  configurationId: "configuration-fallback-high",
  providerId: "provider-fallback",
  modelId: "model-fallback",
  displayName: "Fallback Model",
  reasoningEffort: "high",
});
const unavailable = catalogItem({
  configurationId: "configuration-unavailable",
  providerId: "provider-unavailable",
  modelId: "model-unavailable",
  reasoningEffort: null,
  selectable: false,
  authState: "unconfigured",
  healthState: "unavailable",
  enforcementMode: "unavailable",
  unavailableReasons: [
    "Provider authentication is unavailable.",
    "Provider health check is failing.",
  ],
});
const observeOnly = catalogItem({
  configurationId: "configuration-observe-only",
  providerId: "provider-observe",
  modelId: "model-observe",
  reasoningEffort: null,
  enforcementMode: "observe_only_executor",
});
const advisorOnly = catalogItem({
  configurationId: "configuration-advisor-only",
  providerId: "provider-advisor",
  modelId: "model-advisor",
  reasoningEffort: null,
  enforcementMode: "advisor_only",
});

const catalog: ModelCatalog = {
  schemaVersion: "2.4",
  observedAt: OBSERVED_AT,
  items: [
    primaryLow,
    primaryHigh,
    fallbackLow,
    fallbackHigh,
    observeOnly,
    advisorOnly,
    unavailable,
  ],
};

const receipt: AutonomousAgentModelAssignmentReceipt = {
  agentId: "ReconScout",
  source: "recommended",
  ready: true,
  reasons: [],
  primary: {
    configurationId: primaryLow.configurationId,
    providerId: primaryLow.providerId,
    modelId: primaryLow.modelId,
    displayName: primaryLow.displayName,
    executionBoundary: primaryLow.executionBoundary,
    reasoningEffort: primaryLow.reasoningEffort,
    enforcementMode: primaryLow.enforcementMode,
    authState: primaryLow.authState,
    healthState: primaryLow.healthState,
    disclosureClass: primaryLow.disclosureClass,
    costClass: primaryLow.costClass,
    latencyClass: primaryLow.latencyClass,
    contextLimit: primaryLow.contextLimit,
    catalogSource: primaryLow.catalogSource,
    catalogRetrievedAt: primaryLow.catalogRetrievedAt,
  },
  fallback: null,
};

describe("mission-local agent model assignment state", () => {
  test("materializes recommendations for display while retaining only explicit overrides", () => {
    expect(exactAssignmentFromReceipt(receipt)).toEqual({
      agentId: "ReconScout",
      primaryConfigurationId: "configuration-primary-low",
      fallbackConfigurationId: null,
    });
    expect(assignmentForAgent("ReconScout", undefined, [receipt])).toEqual(
      exactAssignmentFromReceipt(receipt),
    );

    const overridden = upsertAgentModelAssignment(undefined, {
      agentId: "ReconScout",
      primaryConfigurationId: primaryHigh.configurationId,
      fallbackConfigurationId: fallbackHigh.configurationId,
    });
    expect(overridden).toEqual([{
      agentId: "ReconScout",
      primaryConfigurationId: primaryHigh.configurationId,
      fallbackConfigurationId: fallbackHigh.configurationId,
    }]);
    expect(filterAgentModelAssignments(overridden, ["WebBreaker"])).toEqual([]);
    expect(filterAgentModelAssignments(undefined, ["ReconScout"])).toBeUndefined();
  });

  test("selects only live agent-compatible exact configurations and preserves reasoning", () => {
    expect(configurationSelectableForAgent(primaryHigh, "ReconScout")).toBe(true);
    expect(configurationSelectableForAgent(unavailable, "ReconScout")).toBe(false);
    expect(configurationSelectableForAgent(observeOnly, "ReconScout")).toBe(false);
    expect(configurationSelectableForAgent(advisorOnly, "ReconScout")).toBe(false);
    expect(preferredConfigurationForModel(
      [primaryLow, primaryHigh],
      "ReconScout",
      "model-primary",
      "high",
    )?.configurationId).toBe(primaryHigh.configurationId);
    expect(preferredConfigurationForModel(
      [fallbackLow, fallbackHigh],
      "ReconScout",
      "model-fallback",
      "missing",
    )?.configurationId).toBe(fallbackLow.configurationId);
  });

  test("renders six application-owned selectors, exact receipts, and unavailable reasons", () => {
    const markup = renderToStaticMarkup(<MissionAgentModelAssignments
      idPrefix="autonomous-intake-team"
      agents={[{
        id: "ReconScout",
        displayName: "ReconScout",
        role: "Reconnaissance specialist",
      }]}
      selectedAgentIds={["ReconScout"]}
      receipts={[receipt]}
      catalog={catalog}
      catalogUpdatedAt={Date.now()}
      catalogLoading={false}
      readinessStale={false}
      restoreLabel="Restore recommended models"
      onAssignmentsChange={() => undefined}
      onRestore={() => undefined}
    />);
    expect(markup).toContain('aria-label="ReconScout primary provider"');
    expect(markup).toContain('aria-label="ReconScout primary model"');
    expect(markup).toContain('aria-label="ReconScout reasoning effort"');
    expect(markup).toContain('aria-label="ReconScout fallback provider"');
    expect(markup).toContain('aria-label="ReconScout fallback model"');
    expect(markup).toContain('aria-label="ReconScout fallback reasoning effort"');
    expect(markup).toContain("configuration-primary-low");
    expect(markup).toContain("Locally enforced deterministic policy");
    expect(markup).toContain("Provider authentication is unavailable.");
    expect(markup).toContain("provider-unavailable — unavailable for this specialist");
    expect(markup).toContain(
      '<option value="provider-observe" disabled="">provider-observe — unavailable for this specialist</option>',
    );
    expect(markup).toContain(
      '<option value="provider-advisor" disabled="">provider-advisor — unavailable for this specialist</option>',
    );
  });

  test("keeps a removed configuration ID visible as catalog drift", () => {
    const markup = renderToStaticMarkup(<MissionAgentModelAssignments
      idPrefix="autonomous-branch"
      agents={[{
        id: "ReconScout",
        displayName: "ReconScout",
        role: "Reconnaissance specialist",
      }]}
      selectedAgentIds={["ReconScout"]}
      receipts={[]}
      explicitAssignments={[{
        agentId: "ReconScout",
        primaryConfigurationId: "configuration-removed-from-catalog",
        fallbackConfigurationId: null,
      }]}
      catalog={catalog}
      catalogUpdatedAt={Date.now()}
      catalogLoading={false}
      readinessStale
      restoreLabel="Restore signed models"
      onAssignmentsChange={() => undefined}
      onRestore={() => undefined}
    />);
    expect(markup).toContain("Preserved primary configuration");
    expect(markup).toContain("configuration-removed-from-catalog");
    expect(markup).toContain("absent from the current live catalog");
  });

  test("disables restore when the selected assignments already equal the signed baseline", () => {
    const assignment = {
      agentId: "ReconScout",
      primaryConfigurationId: primaryLow.configurationId,
      fallbackConfigurationId: null,
    } as const;
    const markup = renderToStaticMarkup(<MissionAgentModelAssignments
      idPrefix="autonomous-branch"
      agents={[{
        id: "ReconScout",
        displayName: "ReconScout",
        role: "Reconnaissance specialist",
      }]}
      selectedAgentIds={["ReconScout"]}
      receipts={[receipt]}
      explicitAssignments={[assignment]}
      baselineAssignments={[assignment]}
      catalog={catalog}
      catalogUpdatedAt={Date.now()}
      catalogLoading={false}
      readinessStale
      restoreLabel="Restore signed models"
      restoreControlId="autonomous-branch-model-restore-signed"
      onAssignmentsChange={() => undefined}
      onRestore={() => undefined}
    />);
    expect(markup).toContain(
      'data-control-id="autonomous-branch-model-restore-signed" disabled=""',
    );
  });

  test("retires cached selector choices after a refresh failure", () => {
    const markup = renderToStaticMarkup(<MissionAgentModelAssignments
      idPrefix="autonomous-intake-team"
      agents={[{
        id: "ReconScout",
        displayName: "ReconScout",
        role: "Reconnaissance specialist",
      }]}
      selectedAgentIds={["ReconScout"]}
      receipts={[receipt]}
      catalog={catalog}
      catalogUpdatedAt={Date.now()}
      catalogLoading={false}
      catalogError={new Error("Live model catalog refresh failed")}
      readinessStale={false}
      restoreLabel="Restore recommended models"
      onAssignmentsChange={() => undefined}
      onRestore={() => undefined}
    />);
    expect(markup).toContain("Live model catalog refresh failed");
    expect(markup).not.toContain('aria-label="ReconScout primary provider"');
  });

  test("retires cached selector choices when the client trust window expires", () => {
    const markup = renderToStaticMarkup(<MissionAgentModelAssignments
      idPrefix="autonomous-intake-team"
      agents={[{
        id: "ReconScout",
        displayName: "ReconScout",
        role: "Reconnaissance specialist",
      }]}
      selectedAgentIds={["ReconScout"]}
      receipts={[receipt]}
      catalog={catalog}
      catalogUpdatedAt={Date.now() - MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS - 1}
      catalogLoading={false}
      readinessStale={false}
      restoreLabel="Restore recommended models"
      onAssignmentsChange={() => undefined}
      onRestore={() => undefined}
    />);
    expect(markup).toContain("exceeded its 15-minute trust window");
    expect(markup).not.toContain('aria-label="ReconScout primary provider"');
  });
});
